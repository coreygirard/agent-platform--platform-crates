//! A DynamoDB handle for the hardened data-plane vault that **cannot express a
//! delete**.
//!
//! # Why this exists
//!
//! The vault account (`081348549030`) holds the platform's durable tables —
//! `t_drive_items`, `t_drive_coowned`, `t_chirp-auth_vault`, `t_granite_vault`,
//! `t_shriek_vault`, `t_amber-git_refs`, `t_spend_ledger`. Every runtime role
//! that reaches them (`t_drive_runtime`, `t_chirp-auth_runtime`,
//! `t_granite_runtime`, `t_shriek_runtime`) is granted exactly:
//!
//! ```text
//! GetItem BatchGetItem Query Scan DescribeTable PutItem UpdateItem
//! ```
//!
//! `DeleteItem` is **withheld**, on purpose: irreversible destruction in the
//! vault is reserved for the email-gated deletion delegate. That is the central
//! guarantee of the hardened data plane.
//!
//! Until this crate, the guarantee was enforced in exactly two places — IAM at
//! runtime, and the memory of whoever was writing the store. Nothing stopped a
//! store method from calling `.delete_item()`; it compiled, passed review, and
//! passed tests. The three services that reach the vault had three different
//! answers:
//!
//! * **chirp-auth** got it right — routes by key and tombstones the vault path,
//!   with a `ScratchKey` type making a TTL-write to the vault structurally
//!   impossible.
//! * **drive** got it right by construction — its one production delete targets
//!   the erasure-KEY table in drive's own account, never a vault row. That is
//!   what crypto-shred is for.
//! * **shriek** did not. On 2026-08-24 a source-retirement feature shipped as
//!   `DeleteItem` and returned **500 on every call in production**:
//!   `shriek dynamo error: remove expectation: service error`.
//!
//! Two details make that worth a type rather than another comment. The
//! constraint was *already documented in both module headers of the files being
//! edited* ("IAM withholds `DeleteItem`") and was still missed. And the unit
//! tests could not catch it: the in-memory double modelled no permission
//! boundary, so 40 green tests certified an operation production forbids. A
//! test double more permissive than the real store is worse than no test.
//!
//! # What this does
//!
//! [`VaultClient`] owns the SDK client privately and re-exposes only the
//! permitted operations. `.delete_item()` is not a method that exists; the
//! failure moves from a production 500 to a compile error, which is the whole
//! point.
//!
//! ```ignore
//! let vault = VaultClient::new(sdk_client);
//! vault.update_item().table_name(t).key("pk", pk)      // fine
//!      .update_expression("SET #d = :t") /* … */;
//! vault.delete_item();                                  // does not compile
//! ```
//!
//! To retire a vault row, **tombstone it**: an additive `UpdateItem` marking the
//! row, with every read path filtering marked rows. Guard it with
//! `condition_expression("attribute_exists(pk)")` so retiring an absent key is a
//! no-op rather than a silent upsert that creates a tombstone and reports
//! success.
//!
//! # What this does NOT do
//!
//! It is not a security boundary — IAM is, and it still is. Anyone can hold the
//! raw SDK client alongside this one. It removes the *accident*: the store
//! author who reaches for the obvious method and learns from production that
//! the platform forbids it.

#![forbid(unsafe_code)]

use aws_sdk_dynamodb::operation::{
    batch_get_item::builders::BatchGetItemFluentBuilder,
    describe_table::builders::DescribeTableFluentBuilder,
    get_item::builders::GetItemFluentBuilder, put_item::builders::PutItemFluentBuilder,
    query::builders::QueryFluentBuilder, scan::builders::ScanFluentBuilder,
    update_item::builders::UpdateItemFluentBuilder,
};
use aws_sdk_dynamodb::Client;

/// # The invariant, as a test
///
/// A permitted operation compiles. This is the POSITIVE CONTROL, and it is not
/// decoration: a `compile_fail` doctest passes when compilation fails for ANY
/// reason, including a typo in the type name. Without a companion that must
/// compile, the test below would still "pass" if this crate stopped existing.
///
/// ```
/// fn permitted(v: &platform_vault_dynamo::VaultClient) {
///     let _ = v.update_item();
///     let _ = v.put_item();
///     let _ = v.query();
/// }
/// ```
///
/// A withheld operation does not compile — the vault grants no `DeleteItem`, so
/// the method does not exist on this type:
///
/// ```compile_fail
/// fn forbidden(v: &platform_vault_dynamo::VaultClient) {
///     let _ = v.delete_item();
/// }
/// ```
///
/// Nor the batch/transactional writes that can carry a delete:
///
/// ```compile_fail
/// fn forbidden_batch(v: &platform_vault_dynamo::VaultClient) {
///     let _ = v.batch_write_item();
/// }
/// ```
///
/// A DynamoDB client scoped to the operations the vault's runtime roles grant.
///
/// Construct one wherever a vault-backed table is reached. The inner [`Client`]
/// is private, so the destructive operations IAM refuses are not reachable
/// through this type at all.
#[derive(Clone, Debug)]
pub struct VaultClient {
    inner: Client,
}

impl VaultClient {
    /// Wrap an SDK client as a vault handle.
    ///
    /// Takes the client by value rather than by reference so the caller is
    /// nudged to hold the vault handle *instead of* the raw client, not
    /// alongside it. Nothing enforces that — see "What this does NOT do".
    pub fn new(inner: Client) -> Self {
        Self { inner }
    }

    // --- the granted operations, verbatim from the vault role policy ---------

    pub fn get_item(&self) -> GetItemFluentBuilder {
        self.inner.get_item()
    }
    pub fn batch_get_item(&self) -> BatchGetItemFluentBuilder {
        self.inner.batch_get_item()
    }
    pub fn query(&self) -> QueryFluentBuilder {
        self.inner.query()
    }
    pub fn scan(&self) -> ScanFluentBuilder {
        self.inner.scan()
    }
    pub fn describe_table(&self) -> DescribeTableFluentBuilder {
        self.inner.describe_table()
    }
    pub fn put_item(&self) -> PutItemFluentBuilder {
        self.inner.put_item()
    }
    pub fn update_item(&self) -> UpdateItemFluentBuilder {
        self.inner.update_item()
    }

    // Deliberately absent: delete_item, batch_write_item (it can carry
    // DeleteRequests), transact_write_items (likewise), delete_table,
    // update_table, create_table. If a genuine need appears, add the method
    // AND the IAM action together — never one without the other.
}
