mod priorityset;
use priorityset::PrioritySet;

use async_trait::async_trait;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

pub type Error = Box<dyn std::error::Error + Send + Sync>; // This is constant and should be copy pasted

pub static CREATE_LOCKDOWN_MODES: LazyLock<DashMap<String, Box<dyn CreateLockdownMode>>> =
    LazyLock::new(|| {
        let map: DashMap<String, Box<dyn CreateLockdownMode>> = DashMap::new();

        map.insert("qsl".to_string(), Box::new(qsl::CreateQuickServerLockdown));
        map.insert(
            "tsl".to_string(),
            Box::new(tsl::CreateTraditionalServerLockdown),
        );
        map.insert(
            "scl".to_string(),
            Box::new(scl::CreateSingleChannelLockdown),
        );
        map.insert("role".to_string(), Box::new(role::CreateRoleLockdown));

        map
    });

/// Given a string, returns the lockdown mode
pub fn from_lockdown_mode_string(s: &str) -> Result<Box<dyn LockdownMode>, Error> {
    for pair in CREATE_LOCKDOWN_MODES.iter() {
        let creator = pair.value();
        if let Some(m) = creator.to_lockdown_mode(s)? {
            return Ok(m);
        }
    }

    Err("Unknown lockdown mode".into())
}

/// Change operation, commonly used in lockdown modes
#[derive(Debug, Serialize, Deserialize, Clone, Copy, Hash, PartialEq)]
pub enum ChangeOp {
    Add,
    Remove,
}

impl std::fmt::Display for ChangeOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChangeOp::Add => write!(f, "Add"),
            ChangeOp::Remove => write!(f, "Remove"),
        }
    }
}

/// Returns the critical roles for a [PartialGuild](`serenity::all::PartialGuild`)
///
/// The ``set_member_roles`` here are the pre-defined roles set by the server that should be locked down
/// If ``set_member_roles`` is empty (no overrides), the @everyone role is returned
pub fn get_critical_roles(
    pg: &serenity::all::PartialGuild,
    set_critical_roles: &HashSet<serenity::all::RoleId>,
) -> Result<HashSet<serenity::all::RoleId>, Error> {
    if set_critical_roles.is_empty() {
        // Find the everyone role
        let everyone_role = pg
            .roles
            .iter()
            .find(|r| r.id.get() == pg.id.get())
            .ok_or_else(|| Error::from("No @everyone role found"))?;

        Ok(std::iter::once(everyone_role.id).collect())
    } else {
        Ok(set_critical_roles.clone())
    }
}

pub trait LockdownTestResult
where
    Self: Send + Sync,
{
    /// Returns whether the lockdown can be applied perfectly with the current server layout
    fn can_apply_perfectly(&self) -> bool;

    /// Returns a string representation of the result
    fn display_result(&self, pg: &serenity::all::PartialGuild) -> String;
}

/// To ensure two lockdowns don't conflict with each other, we need some information about what all lockdowns are handling
/// along with what specificity they have
pub struct LockdownModeHandle {
    pub roles: HashSet<serenity::all::RoleId>,
    pub channels: HashSet<serenity::all::ChannelId>,
}

/// To ensure two lockdowns don't conflict with each other, we need some information about what all lockdowns are handling
/// along with what specificity they have
pub struct LockdownModeHandles {
    pub roles: PrioritySet<serenity::all::RoleId>,
    pub channels: PrioritySet<serenity::all::ChannelId>,
}

impl LockdownModeHandles {
    /// `add_handle` adds a handle to the set given the specificity of the handle
    pub fn add_handle(&mut self, handle: LockdownModeHandle, specificity: usize) {
        for role in handle.roles {
            self.roles.add(role, specificity);
        }

        for channel in handle.channels {
            self.channels.add(channel, specificity);
        }
    }

    pub fn remove_handle(&mut self, handle: &LockdownModeHandle, specificity: usize) {
        for role in handle.roles.iter() {
            self.roles.remove(*role, specificity);
        }

        for channel in handle.channels.iter() {
            self.channels.remove(*channel, specificity);
        }
    }

    // A role is locked if it contains all roles of the current *with a lower specificity*
    pub fn is_role_locked(
        &self,
        role: serenity::all::RoleId,
        specificity: usize,
    ) -> Option<(serenity::all::RoleId, usize)> {
        if let Some(current_spec) = self.roles.highest_priority(&role) {
            if current_spec >= specificity {
                return Some((role, current_spec));
            }
        }

        None
    }

    // A channel is locked if it contains all channels of the current *with a lower specificity*
    pub fn is_channel_locked(
        &self,
        channel: serenity::all::ChannelId,
        specificity: usize,
    ) -> Option<(serenity::all::ChannelId, usize)> {
        if let Some(current_spec) = self.channels.highest_priority(&channel) {
            if current_spec >= specificity {
                return Some((channel, current_spec));
            }
        }

        None
    }

    // A handle is redundant if it contains all roles and channels of the current *with a lower specificity*
    pub fn is_redundant(&self, other: &LockdownModeHandle, other_spec: usize) -> bool {
        for role in other.roles.iter() {
            if let Some(current_spec) = self.roles.highest_priority(role) {
                if current_spec >= other_spec {
                    return false;
                }
            } else {
                return false;
            }
        }

        for channel in other.channels.iter() {
            if let Some(current_spec) = self.channels.highest_priority(channel) {
                if current_spec >= other_spec {
                    return false;
                }
            } else {
                return false;
            }
        }

        true
    }
}

/// To allow lockdowns to have access to the low-level data of other lockdowns,
/// this struct contains the roles and channels each lockdown knows about
pub struct LockdownSharableData {
    pub role_permissions: HashMap<serenity::all::RoleId, serenity::all::Permissions>,
    pub channel_permissions:
        HashMap<serenity::all::ChannelId, Vec<serenity::all::PermissionOverwrite>>,
}

/// Trait for creating a lockdown mode
#[async_trait]
pub trait CreateLockdownMode
where
    Self: Send + Sync,
{
    /// Returns the syntax for the lockdown mode
    ///
    /// E.g. `qsl` for Quick Server Lockdown, `scl/{channel_id}` for Single Channel Lockdown
    fn syntax(&self) -> &'static str;

    /// Given the string form of the lockdown mode, returns the lockdown mode
    fn to_lockdown_mode(&self, s: &str) -> Result<Option<Box<dyn LockdownMode>>, Error>;
}

/// Trait for a lockdown mode
#[async_trait]
pub trait LockdownMode
where
    Self: Send + Sync,
{
    /// Returns the creator for the lockdown mode
    fn creator(&self) -> Box<dyn CreateLockdownMode>;

    /// Returns the string form of the lockdown mode
    fn string_form(&self) -> String;

    /// The specificity of the lockdown mode. More specific lockdowns should have higher specificity
    ///
    /// The specificity is used to determine which lockdowns should be applied/reverted in the event of multiple lockdowns
    /// handling the same roles/channels
    fn specificity(&self) -> usize;

    async fn test(
        &self,
        pg: &serenity::all::PartialGuild,
        pgc: &[serenity::all::GuildChannel],
        critical_roles: &HashSet<serenity::all::RoleId>,
        lockdowns: &[Lockdown],
    ) -> Result<Box<dyn LockdownTestResult>, Error>;

    /// Sets up the lockdown mode, returning any data to be stored in database
    async fn setup(
        &self,
        pg: &serenity::all::PartialGuild,
        pgc: &[serenity::all::GuildChannel],
        critical_roles: &HashSet<serenity::all::RoleId>,
        lockdowns: &[Lockdown],
    ) -> Result<serde_json::Value, Error>;

    /// Returns the sharable lockdown data
    fn shareable(&self, data: &serde_json::Value) -> Result<LockdownSharableData, Error>;

    #[allow(clippy::too_many_arguments)]
    async fn create(
        &self,
        pg: &mut serenity::all::PartialGuild,
        pgc: &mut [serenity::all::GuildChannel],
        critical_roles: &HashSet<serenity::all::RoleId>,
        data: &serde_json::Value,
        all_handles: &LockdownModeHandles,
        lockdowns: &[Lockdown],
        cache: Option<&serenity::all::Cache>,
        http: &serenity::all::Http,
    ) -> Result<(), Error>;

    #[allow(clippy::too_many_arguments)]
    async fn revert(
        &self,
        pg: &mut serenity::all::PartialGuild,
        pgc: &mut [serenity::all::GuildChannel],
        critical_roles: &HashSet<serenity::all::RoleId>,
        data: &serde_json::Value,
        all_handles: &LockdownModeHandles,
        lockdowns: &[Lockdown],
        cache: Option<&serenity::all::Cache>,
        http: &serenity::all::Http,
    ) -> Result<(), Error>;

    fn handles(
        &self,
        pg: &serenity::all::PartialGuild,
        pgc: &[serenity::all::GuildChannel],
        critical_roles: &HashSet<serenity::all::RoleId>,
        data: &serde_json::Value,
        lockdowns: &[Lockdown],
    ) -> Result<LockdownModeHandle, Error>;
}

/// Serde serialization for LockdownMode
impl Serialize for Box<dyn LockdownMode> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.string_form().serialize(serializer)
    }
}

/// Serde deserialization for LockdownMode
impl<'de> Deserialize<'de> for Box<dyn LockdownMode> {
    fn deserialize<D>(deserializer: D) -> Result<Box<dyn LockdownMode>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;

        // Call `from_lockdown_mode_string` to get the lockdown mode
        from_lockdown_mode_string(&s).map_err(serde::de::Error::custom)
    }
}

pub struct GuildLockdownSettings {
    pub member_roles: HashSet<serenity::all::RoleId>,
    pub require_correct_layout: bool,
}

impl Default for GuildLockdownSettings {
    fn default() -> Self {
        Self {
            member_roles: HashSet::new(),
            require_correct_layout: true,
        }
    }
}

/// Represents a lockdown
#[derive(serde::Serialize, serde::Deserialize)]
pub struct Lockdown {
    pub id: uuid::Uuid,
    pub reason: String,
    pub r#type: Box<dyn LockdownMode>,
    pub data: serde_json::Value,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl Lockdown {
    /// Merges a set of lockdown sharable data's assuming that least recent lockdowns are first
    fn merge_lsd(lsd: Vec<LockdownSharableData>) -> LockdownSharableData {
        let mut new_channel_perms = std::collections::HashMap::new();

        // Add all new/unique permission overwrites of users/roles
        //
        // If said users overwrites are already present in the map, new overwrites will be ignored.
        //
        // This works because the least recent lockdowns are checked first
        let mut per_channel_done_roles = std::collections::HashMap::new();
        let mut per_channel_done_users = std::collections::HashMap::new();
        for data in lsd.iter() {
            for (channel_id, overwrites) in data.channel_permissions.iter() {
                let done_roles = per_channel_done_roles
                    .entry(channel_id)
                    .or_insert_with(std::collections::HashSet::new);
                let done_users = per_channel_done_users
                    .entry(channel_id)
                    .or_insert_with(std::collections::HashSet::new);
                let channel_pos = new_channel_perms
                    .entry(*channel_id)
                    .or_insert_with(Vec::new);

                for overwrite in overwrites.iter() {
                    match overwrite.kind {
                        serenity::all::PermissionOverwriteType::Role(role_id) => {
                            if !done_roles.contains(&role_id) {
                                channel_pos.push(overwrite.clone());
                                done_roles.insert(role_id);
                            }
                        }
                        serenity::all::PermissionOverwriteType::Member(user_id) => {
                            if !done_users.contains(&user_id) {
                                channel_pos.push(overwrite.clone());
                                done_users.insert(user_id);
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        // Merge role permissions, taking only the first found entry
        let mut new_role_perms = std::collections::HashMap::new();

        for data in lsd {
            for (role_id, perms) in data.role_permissions.iter() {
                if !new_role_perms.contains_key(role_id) {
                    new_role_perms.insert(*role_id, *perms);
                }
            }
        }

        LockdownSharableData {
            role_permissions: new_role_perms,
            channel_permissions: new_channel_perms,
        }
    }

    pub fn get_underlying<T, U>(
        lockdowns: &[Self],
        state: T,
        f: fn(&LockdownSharableData, &T) -> Option<U>,
    ) -> Option<U> {
        // Sort lockdown indexes by creation date with least recent first (reverse)
        let mut lockdown_idxs: Vec<usize> = (0..lockdowns.len()).collect();

        lockdown_idxs.sort_by(|a, b| {
            lockdowns[*a]
                .created_at
                .cmp(&lockdowns[*b].created_at)
                .reverse()
        });

        // Now loop over all lockdowns
        //
        // Because we sorted by creation date, the least recent lockdowns will be checked first
        // hence ensuring the permissions we get are from before lockdowns
        let mut unmerged_lsds = Vec::new();
        for idx in lockdown_idxs {
            let lockdown = &lockdowns[idx];

            match lockdown.r#type.shareable(&lockdown.data) {
                Ok(data) => {
                    unmerged_lsds.push(data);
                }
                Err(e) => {
                    log::error!("Error while getting shareable data: {}", e);
                    continue;
                }
            }
        }

        let merged_lsd = Self::merge_lsd(unmerged_lsds);

        f(&merged_lsd, &state)
    }

    pub fn get_underlying_role_permissions(
        lockdowns: &[Self],
        role_id: serenity::all::RoleId,
    ) -> Option<serenity::all::Permissions> {
        Self::get_underlying(lockdowns, role_id, |data, role_id| {
            data.role_permissions.get(role_id).cloned()
        })
    }

    pub fn get_underlying_channel_permissions(
        lockdowns: &[Self],
        channel_id: serenity::all::ChannelId,
    ) -> Option<Vec<serenity::all::PermissionOverwrite>> {
        Self::get_underlying(lockdowns, channel_id, |data, channel_id| {
            data.channel_permissions.get(channel_id).cloned()
        })
    }
}

pub struct CreateLockdown {
    pub reason: String,
    pub r#type: Box<dyn LockdownMode>,
    pub data: Value,
}

#[allow(async_fn_in_trait)]
pub trait LockdownDataStore: Send + Send {
    /// Returns the guilds lockdown settings
    async fn get_guild_lockdown_settings(
        &self,
        guild_id: serenity::all::GuildId,
    ) -> Result<GuildLockdownSettings, Error>;

    /// Fetches the current list of lockdowns from the database
    async fn get_lockdowns(&self, guild_id: serenity::all::GuildId)
        -> Result<Vec<Lockdown>, Error>;

    /// Inserts a new lockdown into the database
    async fn insert_lockdown(
        &self,
        guild_id: serenity::all::GuildId,
        lockdown: CreateLockdown,
    ) -> Result<Lockdown, Error>;

    /// Removes a lockdown by ID
    async fn remove_lockdown(
        &self,
        guild_id: serenity::all::GuildId,
        id: uuid::Uuid,
    ) -> Result<(), Error>;

    /// Fast guild fetch
    async fn guild(
        &self,
        guild_id: serenity::all::GuildId,
    ) -> Result<serenity::all::PartialGuild, Error>;

    /// Fast guild channels fetch
    async fn guild_channels(
        &self,
        guild_id: serenity::all::GuildId,
    ) -> Result<Vec<serenity::all::GuildChannel>, Error>;

    /// Returns the serenity cache
    fn cache(&self) -> Option<&serenity::all::Cache>;

    /// Returns the serenity http client
    fn http(&self) -> &serenity::all::Http;
}

/// Represents a list of lockdowns
pub struct LockdownSet<T: LockdownDataStore> {
    pub data_store: T,
    pub lockdowns: Vec<Lockdown>,
    pub settings: GuildLockdownSettings,
    pub guild_id: serenity::all::GuildId,
}

impl<T: LockdownDataStore> LockdownSet<T> {
    pub async fn guild(guild_id: serenity::all::GuildId, data_store: T) -> Result<Self, Error> {
        let lockdowns = data_store.get_lockdowns(guild_id).await?;

        let settings = data_store.get_guild_lockdown_settings(guild_id).await?;

        Ok(LockdownSet {
            data_store,
            lockdowns,
            settings,
            guild_id,
        })
    }

    /// Sorts the lockdowns by specificity in descending order
    pub fn sort(&mut self) {
        self.lockdowns
            .sort_by(|a, b| b.r#type.specificity().cmp(&a.r#type.specificity()));
    }

    pub fn get_handles(
        &self,
        pg: &serenity::all::PartialGuild,
        pgc: &[serenity::all::GuildChannel],
    ) -> Result<LockdownModeHandles, Error> {
        let mut handles = LockdownModeHandles {
            roles: PrioritySet::default(),
            channels: PrioritySet::default(),
        };

        for lockdown in self.lockdowns.iter() {
            let handle = lockdown.r#type.handles(
                pg,
                pgc,
                &self.settings.member_roles,
                &lockdown.data,
                &self.lockdowns,
            )?;

            // Extend roles and channels
            handles.add_handle(handle, lockdown.r#type.specificity());
        }

        Ok(handles)
    }

    /// Helper method to apply a lockdown without needing to manually perform fetches
    pub async fn easy_apply(
        &mut self,
        lockdown_type: Box<dyn LockdownMode>,
        reason: &str,
    ) -> Result<uuid::Uuid, Error> {
        let mut pg = self
            .data_store
            .guild(self.guild_id)
            .await
            .map_err(|e| format!("Error while fetching guild: {}", e))?;

        let mut pgc = self
            .data_store
            .guild_channels(self.guild_id)
            .await
            .map_err(|e| format!("Error while fetching guild channels: {}", e))?;

        self.apply(lockdown_type, reason, &mut pg, &mut pgc).await
    }

    /// Adds a lockdown to the set returning the id of the created entry
    pub async fn apply(
        &mut self,
        lockdown_type: Box<dyn LockdownMode>,
        reason: &str,
        pg: &mut serenity::all::PartialGuild,
        pgc: &mut [serenity::all::GuildChannel],
    ) -> Result<uuid::Uuid, Error> {
        let critical_roles = get_critical_roles(pg, &self.settings.member_roles)?;

        // Test new lockdown if required
        if self.settings.require_correct_layout {
            let test_results = lockdown_type
                .test(pg, pgc, &critical_roles, &self.lockdowns)
                .await?;

            if !test_results.can_apply_perfectly() {
                return Err(test_results.display_result(pg).into());
            }
        }

        // Setup the lockdown
        let data = lockdown_type
            .setup(pg, pgc, &critical_roles, &self.lockdowns)
            .await?;

        let current_handles = self.get_handles(pg, pgc)?;

        let created_lockdown = self
            .data_store
            .insert_lockdown(
                self.guild_id,
                CreateLockdown {
                    reason: reason.to_string(),
                    r#type: lockdown_type,
                    data,
                },
            )
            .await?;

        // Apply the lockdown
        created_lockdown
            .r#type
            .create(
                pg,
                pgc,
                &critical_roles,
                &created_lockdown.data,
                &current_handles,
                &self.lockdowns,
                self.data_store.cache(),
                self.data_store.http(),
            )
            .await?;

        // Update self.lockdowns
        let id = created_lockdown.id;
        self.lockdowns.push(created_lockdown);

        Ok(id)
    }

    /// Helper method to apply a lockdown without needing to manually perform fetches
    pub async fn easy_remove(&mut self, id: uuid::Uuid) -> Result<(), Error> {
        let mut pg = self
            .data_store
            .guild(self.guild_id)
            .await
            .map_err(|e| format!("Error while fetching guild: {}", e))?;

        let mut pgc = self
            .data_store
            .guild_channels(self.guild_id)
            .await
            .map_err(|e| format!("Error while fetching guild channels: {}", e))?;

        self.remove(id, &mut pg, &mut pgc).await
    }

    /// Removes a lockdown from the set
    pub async fn remove(
        &mut self,
        id: uuid::Uuid,
        pg: &mut serenity::all::PartialGuild,
        pgc: &mut [serenity::all::GuildChannel],
    ) -> Result<(), Error> {
        let lockdown = self
            .lockdowns
            .iter()
            .find(|l| l.id == id)
            .ok_or("Lockdown not found")?;

        let critical_roles = get_critical_roles(pg, &self.settings.member_roles)?;

        let mut current_handles = self.get_handles(pg, pgc)?;

        // Remove handle from the set
        let handle =
            lockdown
                .r#type
                .handles(pg, pgc, &critical_roles, &lockdown.data, &self.lockdowns)?;

        current_handles.remove_handle(&handle, lockdown.r#type.specificity());

        // Revert the lockdown
        lockdown
            .r#type
            .revert(
                pg,
                pgc,
                &critical_roles,
                &lockdown.data,
                &current_handles,
                &self.lockdowns,
                self.data_store.cache(),
                self.data_store.http(),
            )
            .await?;

        // Remove the lockdown from the database
        self.data_store.remove_lockdown(self.guild_id, id).await?;

        // Find new index to avoid a TOCTOU
        if let Some(index) = self.lockdowns.iter().position(|l| l.id == id) {
            self.lockdowns.remove(index);
        }

        Ok(())
    }

    /// Remove all lockdowns in order of specificity
    pub async fn remove_all(
        &mut self,
        pg: &mut serenity::all::PartialGuild,
        pgc: &mut [serenity::all::GuildChannel],
    ) -> Result<(), Error> {
        self.sort();

        let ids = self.lockdowns.iter().map(|l| l.id).collect::<Vec<_>>();

        for id in ids {
            self.remove(id, pg, pgc).await?;
        }

        // Update self.lockdowns
        self.lockdowns.clear();

        Ok(())
    }
}

/// Quick server lockdown
pub mod qsl {
    use super::*;
    use serde::{Deserialize, Serialize};

    /// The base permissions for quick lockdown
    ///
    /// If any of these permissions are provided, quick lockdown cannot proceed
    static BASE_PERMS: [serenity::all::Permissions; 2] = [
        serenity::all::Permissions::VIEW_CHANNEL,
        serenity::all::Permissions::SEND_MESSAGES,
    ];

    static LOCKDOWN_PERMS: std::sync::LazyLock<serenity::all::Permissions> =
        std::sync::LazyLock::new(|| serenity::all::Permissions::VIEW_CHANNEL);

    /// The result of a `test_quick_lockdown` call
    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub struct QuickLockdownTestResult {
        /// Which roles need to be changed/fixed combined with the target perms
        pub changes_needed: std::collections::HashMap<
            serenity::all::RoleId,
            (ChangeOp, serenity::all::Permissions),
        >,
        /// The critical roles
        pub critical_roles: HashSet<serenity::all::RoleId>,
    }

    impl LockdownTestResult for QuickLockdownTestResult {
        /// Returns whether the guild is in a state where quick lockdown can be applied perfectly
        fn can_apply_perfectly(&self) -> bool {
            self.changes_needed.is_empty()
        }

        fn display_result(&self, pg: &serenity::all::PartialGuild) -> String {
            let mut needed_changes = String::new();

            needed_changes.push_str("The following roles need to be changed:\n");
            for (role_id, perms) in self.changes_needed.iter() {
                let role_name = pg
                    .roles
                    .get(role_id)
                    .map(|r| r.name.to_string())
                    .unwrap_or_else(|| "Unknown".to_string());

                needed_changes.push_str(&format!("Role: {} ({})\n", role_name, role_id));
                needed_changes.push_str(&format!("Permissions: {} {}\n", perms.0, perms.1));
                needed_changes.push('\n');
            }

            needed_changes
        }
    }

    pub struct CreateQuickServerLockdown;

    #[async_trait]
    impl CreateLockdownMode for CreateQuickServerLockdown {
        fn syntax(&self) -> &'static str {
            "qsl"
        }

        fn to_lockdown_mode(&self, s: &str) -> Result<Option<Box<dyn LockdownMode>>, Error> {
            if s == "qsl" {
                Ok(Some(Box::new(QuickServerLockdown)))
            } else {
                Ok(None)
            }
        }
    }

    pub struct QuickServerLockdown;

    impl QuickServerLockdown {
        pub fn from_data(
            data: &serde_json::Value,
        ) -> Result<
            std::collections::HashMap<serenity::all::RoleId, serenity::all::Permissions>,
            Error,
        > {
            let v: std::collections::HashMap<serenity::all::RoleId, serenity::all::Permissions> =
                serde_json::from_value(data.clone())
                    .map_err(|e| format!("Error while deserializing permissions: {}", e))?;

            Ok(v)
        }
    }

    #[async_trait]
    impl LockdownMode for QuickServerLockdown {
        fn creator(&self) -> Box<dyn CreateLockdownMode> {
            Box::new(CreateQuickServerLockdown)
        }

        fn string_form(&self) -> String {
            "qsl".to_string()
        }

        // Lowest specificity
        fn specificity(&self) -> usize {
            0
        }

        async fn test(
            &self,
            pg: &serenity::all::PartialGuild,
            _pgc: &[serenity::all::GuildChannel],
            critical_roles: &HashSet<serenity::all::RoleId>,
            _lockdowns: &[Lockdown], // We dont need to care about other lockdowns
        ) -> Result<Box<dyn LockdownTestResult>, Error> {
            let mut changes_needed = std::collections::HashMap::new();

            // From here on out, we only need to care about critical and non critical roles
            for role in pg.roles.iter() {
                if critical_roles.contains(&role.id) {
                    let mut needed_perms = serenity::all::Permissions::empty();

                    let mut missing = false;
                    for perm in BASE_PERMS {
                        if !role.permissions.contains(perm) {
                            needed_perms |= perm;
                            missing = true;
                        }
                    }

                    if missing {
                        changes_needed.insert(role.id, (ChangeOp::Add, needed_perms));
                    }
                } else {
                    let mut perms_to_remove = serenity::all::Permissions::empty();

                    let mut needs_perms_removed = false;
                    for perm in BASE_PERMS {
                        if role.permissions.contains(perm) {
                            perms_to_remove |= perm;
                            needs_perms_removed = true;
                        }
                    }

                    if needs_perms_removed {
                        changes_needed.insert(role.id, (ChangeOp::Remove, perms_to_remove));
                    }
                }
            }

            Ok(Box::new(QuickLockdownTestResult {
                changes_needed,
                critical_roles: critical_roles.clone(),
            }))
        }

        async fn setup(
            &self,
            pg: &serenity::all::PartialGuild,
            _pgc: &[serenity::all::GuildChannel],
            _critical_roles: &HashSet<serenity::all::RoleId>,
            lockdowns: &[Lockdown], // We dont need to care about other lockdowns
        ) -> Result<serde_json::Value, Error> {
            let mut map = serde_json::Map::new();

            for role in pg.roles.iter() {
                let mut permissions = role.permissions;

                // Check for an underlying permission overwrite to the channel
                if let Some(underlying_permissions) =
                    Lockdown::get_underlying_role_permissions(lockdowns, role.id)
                {
                    permissions = underlying_permissions; // Overwrite the permissions
                }

                map.insert(
                    role.id.to_string(),
                    serde_json::Value::String(permissions.bits().to_string()),
                );
            }

            Ok(serde_json::Value::Object(map))
        }

        fn shareable(&self, data: &serde_json::Value) -> Result<LockdownSharableData, Error> {
            let data = Self::from_data(data)?;
            Ok(LockdownSharableData {
                role_permissions: data,
                channel_permissions: HashMap::new(),
            })
        }

        async fn create(
            &self,
            pg: &mut serenity::all::PartialGuild,
            _pgc: &mut [serenity::all::GuildChannel],
            critical_roles: &HashSet<serenity::all::RoleId>,
            _data: &serde_json::Value,
            _all_handles: &LockdownModeHandles,
            _lockdowns: &[Lockdown], // We dont need to care about other lockdowns
            _cache: Option<&serenity::all::Cache>,
            http: &serenity::all::Http,
        ) -> Result<(), Error> {
            let mut new_roles = Vec::new();
            for role in pg.roles.iter() {
                // If critical, lock it down
                if critical_roles.contains(&role.id) {
                    new_roles.push(
                        pg.id
                            .edit_role(
                                http,
                                role.id,
                                serenity::all::EditRole::new().permissions(*LOCKDOWN_PERMS),
                            )
                            .await?,
                    );
                }
            }

            for role in new_roles {
                pg.roles.insert(role);
            }

            Ok(())
        }

        async fn revert(
            &self,
            pg: &mut serenity::all::PartialGuild,
            _pgc: &mut [serenity::all::GuildChannel],
            critical_roles: &HashSet<serenity::all::RoleId>,
            data: &serde_json::Value,
            _all_handles: &LockdownModeHandles,
            _lockdowns: &[Lockdown], // We dont need to care about other lockdowns
            _cache: Option<&serenity::all::Cache>,
            http: &serenity::all::Http,
        ) -> Result<(), Error> {
            let old_permissions = Self::from_data(data)?;

            let mut new_roles = Vec::new();
            for role in pg.roles.iter() {
                if critical_roles.contains(&role.id) {
                    let perms = old_permissions.get(&role.id).copied().unwrap_or(
                        BASE_PERMS
                            .iter()
                            .copied()
                            .fold(serenity::all::Permissions::empty(), |acc, perm| acc | perm),
                    );

                    new_roles.push(
                        pg.id
                            .edit_role(
                                http,
                                role.id,
                                serenity::all::EditRole::new().permissions(perms),
                            )
                            .await?,
                    );
                }
            }

            for role in new_roles {
                pg.roles.insert(role);
            }

            Ok(())
        }

        fn handles(
            &self,
            _pg: &serenity::all::PartialGuild,
            _pgc: &[serenity::all::GuildChannel],
            critical_roles: &HashSet<serenity::all::RoleId>,
            _data: &serde_json::Value,
            _lockdowns: &[Lockdown], // We dont need to care about other lockdowns
        ) -> Result<LockdownModeHandle, Error> {
            // QSL locks the critical roles
            Ok(LockdownModeHandle {
                roles: critical_roles.clone(),
                channels: HashSet::new(),
            })
        }
    }
}

/// Traditional server lockdown (lock all channels)
pub mod tsl {
    use super::*;
    use serde::{Deserialize, Serialize};

    static DENY_PERMS: std::sync::LazyLock<serenity::all::Permissions> =
        std::sync::LazyLock::new(|| {
            serenity::all::Permissions::SEND_MESSAGES
                | serenity::all::Permissions::SEND_MESSAGES_IN_THREADS
                | serenity::all::Permissions::SEND_TTS_MESSAGES
                | serenity::all::Permissions::CONNECT
        });

    // The big advantage of TSL is the lack of constraints/tests regarding server layout
    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub struct TraditionalLockdownTestResult;

    impl LockdownTestResult for TraditionalLockdownTestResult {
        fn can_apply_perfectly(&self) -> bool {
            log::info!("Called can_apply_perfectly");
            true
        }

        fn display_result(&self, _pg: &serenity::all::PartialGuild) -> String {
            "".to_string()
        }
    }

    pub struct CreateTraditionalServerLockdown;

    #[async_trait]
    impl CreateLockdownMode for CreateTraditionalServerLockdown {
        fn syntax(&self) -> &'static str {
            "tsl"
        }

        fn to_lockdown_mode(&self, s: &str) -> Result<Option<Box<dyn LockdownMode>>, Error> {
            if s == "tsl" {
                Ok(Some(Box::new(TraditionalServerLockdown)))
            } else {
                Ok(None)
            }
        }
    }

    pub struct TraditionalServerLockdown;

    impl TraditionalServerLockdown {
        pub fn from_data(
            data: &serde_json::Value,
        ) -> Result<
            std::collections::HashMap<
                serenity::all::ChannelId,
                Vec<serenity::all::PermissionOverwrite>,
            >,
            Error,
        > {
            log::info!("Called from_data");
            let v: std::collections::HashMap<
                serenity::all::ChannelId,
                Vec<serenity::all::PermissionOverwrite>,
            > = serde_json::from_value(data.clone())
                .map_err(|e| format!("Error while deserializing permissions: {}", e))?;

            Ok(v)
        }
    }

    #[async_trait]
    impl LockdownMode for TraditionalServerLockdown {
        fn creator(&self) -> Box<dyn CreateLockdownMode> {
            Box::new(CreateTraditionalServerLockdown)
        }

        fn string_form(&self) -> String {
            "tsl".to_string()
        }

        // TSL > QSL as it updates all channels in a server
        fn specificity(&self) -> usize {
            1
        }

        // TSL doesn't need to test anything so just return the result
        async fn test(
            &self,
            _pg: &serenity::all::PartialGuild,
            _pgc: &[serenity::all::GuildChannel],
            _critical_roles: &HashSet<serenity::all::RoleId>,
            _lockdowns: &[Lockdown],
        ) -> Result<Box<dyn LockdownTestResult>, Error> {
            log::info!("Called test");
            Ok(Box::new(TraditionalLockdownTestResult))
        }

        async fn setup(
            &self,
            _pg: &serenity::all::PartialGuild,
            pgc: &[serenity::all::GuildChannel],
            _critical_roles: &HashSet<serenity::all::RoleId>,
            lockdowns: &[Lockdown],
        ) -> Result<serde_json::Value, Error> {
            log::info!("Called setup");
            let mut map = serde_json::Map::new();

            for channel in pgc.iter() {
                let mut overwrites = channel.permission_overwrites.to_vec();

                // Check for an underlying permission overwrite to the channel
                if let Some(underlying_overwrite) =
                    Lockdown::get_underlying_channel_permissions(lockdowns, channel.id)
                {
                    overwrites = underlying_overwrite; // Overwrite the overwrites
                }

                map.insert(channel.id.to_string(), serde_json::to_value(overwrites)?);
            }

            Ok(serde_json::Value::Object(map))
        }

        fn shareable(&self, data: &serde_json::Value) -> Result<LockdownSharableData, Error> {
            let data = Self::from_data(data)?;
            Ok(LockdownSharableData {
                role_permissions: HashMap::new(),
                channel_permissions: data,
            })
        }

        async fn create(
            &self,
            _pg: &mut serenity::all::PartialGuild,
            pgc: &mut [serenity::all::GuildChannel],
            critical_roles: &HashSet<serenity::all::RoleId>,
            _data: &serde_json::Value,
            all_handles: &LockdownModeHandles,
            _lockdowns: &[Lockdown],
            _cache: Option<&serenity::all::Cache>,
            http: &serenity::all::Http,
        ) -> Result<(), Error> {
            log::info!("Called create");
            for channel in pgc.iter_mut() {
                if all_handles
                    .is_channel_locked(channel.id, self.specificity())
                    .is_some()
                {
                    continue; // Someone else is handling this channel
                }

                let mut overwrites = channel.permission_overwrites.to_vec();

                let mut nyset_overwrite = critical_roles.clone();
                for overwrite in overwrites.iter_mut() {
                    match overwrite.kind {
                        serenity::all::PermissionOverwriteType::Role(role_id) => {
                            if critical_roles.contains(&role_id) {
                                overwrite.deny = *DENY_PERMS;
                                nyset_overwrite.remove(&role_id);
                            }
                        }
                        _ => continue,
                    }
                }

                if !nyset_overwrite.is_empty() {
                    for critical_role in nyset_overwrite.iter() {
                        let overwrite = serenity::all::PermissionOverwrite {
                            allow: serenity::all::Permissions::empty(),
                            deny: *DENY_PERMS,
                            kind: serenity::all::PermissionOverwriteType::Role(*critical_role),
                        };

                        overwrites.push(overwrite);
                    }
                }

                match channel
                    .edit(
                        http,
                        serenity::all::EditChannel::new().permissions(overwrites),
                    )
                    .await
                {
                    Ok(_) => {}
                    Err(e) => match e {
                        serenity::Error::Http(e) => match e {
                            serenity::all::HttpError::UnsuccessfulRequest(er) => {
                                if er.status_code == reqwest::StatusCode::NOT_FOUND {
                                    log::info!("Channel not found: {}", channel.id);
                                    continue; // Rare, but sometimes happens (?)
                                } else {
                                    return Err(format!(
                                        "Failed to create channel lockdown (http, non-404) {}: {:?}",
                                        channel.id, er
                                    )
                                    .into());
                                }
                            }
                            _ => {
                                return Err(format!(
                                    "Failed to create channel lockdown (http) {}: {:?}",
                                    channel.id, e
                                )
                                .into());
                            }
                        },
                        _ => {
                            return Err(format!(
                                "Failed to create channel lockdown {}: {:?}",
                                channel.id, e
                            )
                            .into());
                        }
                    },
                };
            }

            Ok(())
        }

        async fn revert(
            &self,
            _pg: &mut serenity::all::PartialGuild,
            pgc: &mut [serenity::all::GuildChannel],
            _critical_roles: &HashSet<serenity::all::RoleId>,
            data: &serde_json::Value,
            all_handles: &LockdownModeHandles,
            _lockdowns: &[Lockdown],
            _cache: Option<&serenity::all::Cache>,
            http: &serenity::all::Http,
        ) -> Result<(), Error> {
            log::info!("Called revert");
            let old_permissions = Self::from_data(data)?;

            for channel in pgc.iter_mut() {
                if all_handles
                    .is_channel_locked(channel.id, self.specificity())
                    .is_some()
                {
                    continue; // Someone else is handling this channel
                }

                // TODO: Handle this slightly better (maybe only apply the changes to critical roles somehow)
                let Some(overwrites) = old_permissions.get(&channel.id).cloned() else {
                    continue;
                };

                match channel
                    .edit(
                        http,
                        serenity::all::EditChannel::new().permissions(overwrites),
                    )
                    .await
                {
                    Ok(_) => {}
                    Err(e) => match e {
                        serenity::Error::Http(e) => match e {
                            serenity::all::HttpError::UnsuccessfulRequest(er) => {
                                if er.status_code == reqwest::StatusCode::NOT_FOUND {
                                    continue; // Rare, but sometimes happens (?)
                                } else {
                                    return Err(format!(
                                        "Failed to delete channel lockdown (http, non-404) {}: {:?}",
                                        channel.id, er
                                    )
                                    .into());
                                }
                            }
                            _ => {
                                return Err(format!(
                                    "Failed to delete channel lockdown (http) {}: {:?}",
                                    channel.id, e
                                )
                                .into());
                            }
                        },
                        _ => {
                            return Err(format!(
                                "Failed to delete channel lockdown {}: {:?}",
                                channel.id, e
                            )
                            .into());
                        }
                    },
                };
            }

            Ok(())
        }

        fn handles(
            &self,
            _pg: &serenity::all::PartialGuild,
            pgc: &[serenity::all::GuildChannel],
            _critical_roles: &HashSet<serenity::all::RoleId>,
            _data: &serde_json::Value,
            _lockdowns: &[Lockdown],
        ) -> Result<LockdownModeHandle, Error> {
            // TSL locks all channels, but *NOT* roles
            Ok(LockdownModeHandle {
                roles: HashSet::new(),
                channels: pgc.iter().map(|c| c.id).collect(),
            })
        }
    }
}

/// Single channel lock
pub mod scl {
    use super::*;
    use serde::{Deserialize, Serialize};

    static DENY_PERMS: std::sync::LazyLock<serenity::all::Permissions> =
        std::sync::LazyLock::new(|| {
            serenity::all::Permissions::SEND_MESSAGES
                | serenity::all::Permissions::SEND_MESSAGES_IN_THREADS
                | serenity::all::Permissions::SEND_TTS_MESSAGES
                | serenity::all::Permissions::CONNECT
        });

    // The big advantage of TSL is the lack of constraints/tests regarding server layout
    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub struct SingleChannelLockdownTestResult;

    impl LockdownTestResult for SingleChannelLockdownTestResult {
        fn can_apply_perfectly(&self) -> bool {
            true
        }

        fn display_result(&self, _pg: &serenity::all::PartialGuild) -> String {
            "".to_string()
        }
    }

    pub struct CreateSingleChannelLockdown;

    #[async_trait]
    impl CreateLockdownMode for CreateSingleChannelLockdown {
        fn syntax(&self) -> &'static str {
            "scl/<channel_id>"
        }

        fn to_lockdown_mode(&self, s: &str) -> Result<Option<Box<dyn LockdownMode>>, Error> {
            if s.starts_with("scl/") {
                let channel_id = s
                    .strip_prefix("scl/")
                    .ok_or_else(|| Error::from("Invalid syntax"))?;

                let channel_id = channel_id
                    .parse()
                    .map_err(|e| format!("Error while parsing channel id: {}", e))?;

                Ok(Some(Box::new(SingleChannelLockdown(channel_id))))
            } else {
                Ok(None)
            }
        }
    }

    pub struct SingleChannelLockdown(pub serenity::all::ChannelId);

    impl SingleChannelLockdown {
        pub fn from_data(
            data: &serde_json::Value,
        ) -> Result<Vec<serenity::all::PermissionOverwrite>, Error> {
            let v: Vec<serenity::all::PermissionOverwrite> =
                serde_json::from_value(data.clone())
                    .map_err(|e| format!("Error while deserializing permissions: {}", e))?;

            Ok(v)
        }
    }

    #[async_trait]
    impl LockdownMode for SingleChannelLockdown {
        fn creator(&self) -> Box<dyn CreateLockdownMode> {
            Box::new(CreateSingleChannelLockdown)
        }

        fn string_form(&self) -> String {
            format!("scl/{}", self.0)
        }

        // SCL > TSL as it updates a single channel
        fn specificity(&self) -> usize {
            2
        }

        // SCL doesn't need to test anything so just return the result
        async fn test(
            &self,
            _pg: &serenity::all::PartialGuild,
            _pgc: &[serenity::all::GuildChannel],
            _critical_roles: &HashSet<serenity::all::RoleId>,
            _lockdowns: &[Lockdown],
        ) -> Result<Box<dyn LockdownTestResult>, Error> {
            Ok(Box::new(SingleChannelLockdownTestResult))
        }

        async fn setup(
            &self,
            _pg: &serenity::all::PartialGuild,
            pgc: &[serenity::all::GuildChannel],
            _critical_roles: &HashSet<serenity::all::RoleId>,
            lockdowns: &[Lockdown],
        ) -> Result<serde_json::Value, Error> {
            let channel = pgc
                .iter()
                .find(|c| c.id == self.0)
                .ok_or_else(|| Error::from("Channel not found"))?;

            let mut overwrites = channel.permission_overwrites.to_vec();

            // Check for an underlying permission overwrite to the channel
            if let Some(underlying_overwrite) =
                Lockdown::get_underlying_channel_permissions(lockdowns, channel.id)
            {
                overwrites = underlying_overwrite; // Overwrite the overwrites
            }

            Ok(serde_json::to_value(overwrites)?)
        }

        fn shareable(&self, data: &serde_json::Value) -> Result<LockdownSharableData, Error> {
            let data = Self::from_data(data)?;
            Ok(LockdownSharableData {
                role_permissions: HashMap::new(),
                channel_permissions: std::iter::once((self.0, data)).collect(),
            })
        }

        async fn create(
            &self,
            _pg: &mut serenity::all::PartialGuild,
            _pgc: &mut [serenity::all::GuildChannel],
            critical_roles: &HashSet<serenity::all::RoleId>,
            data: &serde_json::Value,
            all_handles: &LockdownModeHandles,
            _lockdowns: &[Lockdown],
            _cache: Option<&serenity::all::Cache>,
            http: &serenity::all::Http,
        ) -> Result<(), Error> {
            if all_handles
                .is_channel_locked(self.0, self.specificity())
                .is_some()
            {
                return Ok(()); // Someone else is handling this channel
            }

            let mut overwrites = Self::from_data(data)?;

            let mut nyset_overwrite = critical_roles.clone();
            for overwrite in overwrites.iter_mut() {
                match overwrite.kind {
                    serenity::all::PermissionOverwriteType::Role(role_id) => {
                        if critical_roles.contains(&role_id) {
                            overwrite.deny = *DENY_PERMS;
                            nyset_overwrite.remove(&role_id);
                        }
                    }
                    _ => continue,
                }
            }

            if !nyset_overwrite.is_empty() {
                for critical_role in nyset_overwrite.iter() {
                    let overwrite = serenity::all::PermissionOverwrite {
                        allow: serenity::all::Permissions::empty(),
                        deny: *DENY_PERMS,
                        kind: serenity::all::PermissionOverwriteType::Role(*critical_role),
                    };

                    overwrites.push(overwrite);
                }
            }

            self.0
                .edit(
                    http,
                    serenity::all::EditChannel::new().permissions(overwrites),
                )
                .await?;

            Ok(())
        }

        async fn revert(
            &self,
            _pg: &mut serenity::all::PartialGuild,
            _pgc: &mut [serenity::all::GuildChannel],
            _critical_roles: &HashSet<serenity::all::RoleId>,
            data: &serde_json::Value,
            all_handles: &LockdownModeHandles,
            _lockdowns: &[Lockdown],
            _cache: Option<&serenity::all::Cache>,
            http: &serenity::all::Http,
        ) -> Result<(), Error> {
            if all_handles
                .is_channel_locked(self.0, self.specificity())
                .is_some()
            {
                return Ok(()); // Someone else is handling this channel
            }

            let overwrites = Self::from_data(data)?;

            self.0
                .edit(
                    http,
                    serenity::all::EditChannel::new().permissions(overwrites),
                )
                .await?;

            Ok(())
        }

        fn handles(
            &self,
            _pg: &serenity::all::PartialGuild,
            _pgc: &[serenity::all::GuildChannel],
            _critical_roles: &HashSet<serenity::all::RoleId>,
            _data: &serde_json::Value,
            _lockdowns: &[Lockdown],
        ) -> Result<LockdownModeHandle, Error> {
            // SCL locks a single channel
            Ok(LockdownModeHandle {
                roles: HashSet::new(),
                channels: std::iter::once(self.0).collect(),
            })
        }
    }
}

/// Single role lockdown
pub mod role {
    use super::*;
    use serde::{Deserialize, Serialize};

    pub static DENY_PERMS: std::sync::LazyLock<serenity::all::Permissions> =
        std::sync::LazyLock::new(|| {
            serenity::all::Permissions::ADMINISTRATOR
                | serenity::all::Permissions::MANAGE_GUILD
                | serenity::all::Permissions::MANAGE_ROLES
                | serenity::all::Permissions::MANAGE_CHANNELS
                | serenity::all::Permissions::MANAGE_MESSAGES
                | serenity::all::Permissions::MANAGE_WEBHOOKS
                | serenity::all::Permissions::MANAGE_GUILD_EXPRESSIONS
                | serenity::all::Permissions::KICK_MEMBERS
                | serenity::all::Permissions::BAN_MEMBERS
                | serenity::all::Permissions::MODERATE_MEMBERS
                | serenity::all::Permissions::MANAGE_NICKNAMES
                | serenity::all::Permissions::MOVE_MEMBERS
                | serenity::all::Permissions::MUTE_MEMBERS
                | serenity::all::Permissions::DEAFEN_MEMBERS
                | serenity::all::Permissions::MENTION_EVERYONE
                | serenity::all::Permissions::MANAGE_THREADS
        });

    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub struct RoleLockdownTestResult;

    impl LockdownTestResult for RoleLockdownTestResult {
        fn can_apply_perfectly(&self) -> bool {
            true
        }

        fn display_result(&self, _pg: &serenity::all::PartialGuild) -> String {
            "".to_string()
        }
    }

    pub struct CreateRoleLockdown;

    #[async_trait]
    impl CreateLockdownMode for CreateRoleLockdown {
        fn syntax(&self) -> &'static str {
            "role/<role_id>"
        }

        fn to_lockdown_mode(&self, s: &str) -> Result<Option<Box<dyn LockdownMode>>, Error> {
            if s.starts_with("role/") {
                let role_id = s
                    .strip_prefix("role/")
                    .ok_or_else(|| Error::from("Invalid syntax"))?;

                let role_id = role_id
                    .parse()
                    .map_err(|e| format!("Error while parsing role id: {}", e))?;

                Ok(Some(Box::new(RoleLockdown(role_id))))
            } else {
                Ok(None)
            }
        }
    }

    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub struct RoleLockdownData {
        pub global_perms: serenity::all::Permissions,
        pub channel_overrides:
            std::collections::HashMap<serenity::all::ChannelId, serenity::all::PermissionOverwrite>,
    }

    pub struct RoleLockdown(pub serenity::all::RoleId);

    impl RoleLockdown {
        pub fn from_data(data: &serde_json::Value) -> Result<RoleLockdownData, Error> {
            let v: RoleLockdownData = serde_json::from_value(data.clone())
                .map_err(|e| format!("Error while deserializing role data: {}", e))?;

            Ok(v)
        }
    }

    #[async_trait]
    impl LockdownMode for RoleLockdown {
        fn creator(&self) -> Box<dyn CreateLockdownMode> {
            Box::new(CreateRoleLockdown)
        }

        fn string_form(&self) -> String {
            format!("role/{}", self.0)
        }

        // SCL > TSL as it updates a single channel
        fn specificity(&self) -> usize {
            2
        }

        // SCL doesn't need to test anything so just return the result
        async fn test(
            &self,
            _pg: &serenity::all::PartialGuild,
            _pgc: &[serenity::all::GuildChannel],
            _critical_roles: &HashSet<serenity::all::RoleId>,
            _lockdowns: &[Lockdown],
        ) -> Result<Box<dyn LockdownTestResult>, Error> {
            Ok(Box::new(RoleLockdownTestResult))
        }

        async fn setup(
            &self,
            pg: &serenity::all::PartialGuild,
            pgc: &[serenity::all::GuildChannel],
            _critical_roles: &HashSet<serenity::all::RoleId>,
            lockdowns: &[Lockdown],
        ) -> Result<serde_json::Value, Error> {
            let role = pg
                .roles
                .iter()
                .find(|c| c.id == self.0)
                .ok_or_else(|| Error::from("Role not found"))?;

            let mut permissions = role.permissions;

            // Check for an underlying permission to the role
            if let Some(underlying_permissions) =
                Lockdown::get_underlying_role_permissions(lockdowns, role.id)
            {
                permissions = underlying_permissions; // Overwrite the permissions
            }

            let mut overwrites = std::collections::HashMap::new();

            for channel in pgc.iter() {
                let mut overwrite = channel
                    .permission_overwrites
                    .iter()
                    .find(|o| match o.kind {
                        serenity::all::PermissionOverwriteType::Role(role_id) => role_id == self.0,
                        _ => false,
                    })
                    .cloned();

                // Check for an underlying permission overwrite to the channel
                if let Some(underlying_overwrite) =
                    Lockdown::get_underlying_channel_permissions(lockdowns, channel.id)
                {
                    // Try finding the overwrite for this role, override the overwrite if found
                    let mut found = false;

                    for u_overwrite in underlying_overwrite.iter() {
                        match u_overwrite.kind {
                            serenity::all::PermissionOverwriteType::Role(role_id) => {
                                if role_id == self.0 {
                                    overwrite = Some(u_overwrite.clone());
                                    found = true;
                                    break;
                                }
                            }
                            _ => continue,
                        }
                    }

                    if !found {
                        overwrite = None
                    }
                }

                if let Some(overwrite) = overwrite {
                    overwrites.insert(channel.id, overwrite);
                }
            }

            Ok(serde_json::to_value(RoleLockdownData {
                global_perms: permissions,
                channel_overrides: overwrites,
            })?)
        }

        fn shareable(&self, data: &serde_json::Value) -> Result<LockdownSharableData, Error> {
            let data = Self::from_data(data)?;
            Ok(LockdownSharableData {
                role_permissions: std::iter::once((self.0, data.global_perms)).collect(),
                channel_permissions: {
                    let mut map = std::collections::HashMap::new();

                    for (channel_id, overwrite) in data.channel_overrides.into_iter() {
                        map.insert(channel_id, vec![overwrite]);
                    }

                    map
                },
            })
        }

        async fn create(
            &self,
            pg: &mut serenity::all::PartialGuild,
            pgc: &mut [serenity::all::GuildChannel],
            _critical_roles: &HashSet<serenity::all::RoleId>,
            _data: &serde_json::Value,
            all_handles: &LockdownModeHandles,
            _lockdowns: &[Lockdown],
            _cache: Option<&serenity::all::Cache>,
            http: &serenity::all::Http,
        ) -> Result<(), Error> {
            if all_handles
                .is_role_locked(self.0, self.specificity())
                .is_some()
            {
                return Ok(()); // Someone else is handling this role
            }

            // 1. Edit the role
            pg.id
                .edit_role(
                    http,
                    self.0,
                    serenity::all::EditRole::new().permissions(serenity::all::Permissions::empty()),
                )
                .await?;

            // 2. Edit the permission overwrites for each channel
            for ch in pgc.iter_mut() {
                let mut found_overwrite = false;

                let mut overwrites = ch.permission_overwrites.to_vec();

                if let Some(overwrite) = overwrites.iter_mut().find(|o| match o.kind {
                    serenity::all::PermissionOverwriteType::Role(role_id) => role_id == self.0,
                    _ => false,
                }) {
                    found_overwrite = true;
                    overwrite.allow = serenity::all::Permissions::empty();
                    overwrite.deny = *DENY_PERMS;
                }

                if !found_overwrite {
                    overwrites.push(serenity::all::PermissionOverwrite {
                        allow: serenity::all::Permissions::empty(),
                        deny: *DENY_PERMS,
                        kind: serenity::all::PermissionOverwriteType::Role(self.0),
                    });
                }

                ch.edit(
                    http,
                    serenity::all::EditChannel::new().permissions(overwrites),
                )
                .await?;
            }

            Ok(())
        }

        async fn revert(
            &self,
            pg: &mut serenity::all::PartialGuild,
            pgc: &mut [serenity::all::GuildChannel],
            _critical_roles: &HashSet<serenity::all::RoleId>,
            data: &serde_json::Value,
            all_handles: &LockdownModeHandles,
            _lockdowns: &[Lockdown],
            _cache: Option<&serenity::all::Cache>,
            http: &serenity::all::Http,
        ) -> Result<(), Error> {
            if all_handles
                .is_role_locked(self.0, self.specificity())
                .is_some()
            {
                return Ok(()); // Someone else is handling this role
            }

            let rld = Self::from_data(data)?;

            // First edit the role itself
            pg.id
                .edit_role(
                    http,
                    self.0,
                    serenity::all::EditRole::new().permissions(rld.global_perms),
                )
                .await?;

            // Then fix up channels
            for ch in pgc {
                let old_overwrites = rld.channel_overrides.get(&ch.id);

                let mut overwrites = ch.permission_overwrites.to_vec();

                // Remove old/existing overwrites
                let mut found_overwrite = None;
                for (i, overwrite) in overwrites.iter().enumerate() {
                    match overwrite.kind {
                        serenity::all::PermissionOverwriteType::Role(role_id) => {
                            if role_id == self.0 {
                                found_overwrite = Some(i);
                                break;
                            }
                        }
                        _ => continue,
                    }
                }

                if let Some(i) = found_overwrite {
                    overwrites.remove(i);
                }

                // Add back the old overwrite
                if let Some(old_overwrite) = old_overwrites {
                    overwrites.push(old_overwrite.clone());
                }

                ch.edit(
                    http,
                    serenity::all::EditChannel::new().permissions(overwrites),
                )
                .await?;
            }

            Ok(())
        }

        fn handles(
            &self,
            _pg: &serenity::all::PartialGuild,
            _pgc: &[serenity::all::GuildChannel],
            _critical_roles: &HashSet<serenity::all::RoleId>,
            _data: &serde_json::Value,
            _lockdowns: &[Lockdown],
        ) -> Result<LockdownModeHandle, Error> {
            // Role locks a single role
            Ok(LockdownModeHandle {
                roles: std::iter::once(self.0).collect(),
                channels: HashSet::new(),
            })
        }
    }
}
