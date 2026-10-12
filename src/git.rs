use crate::dependency::{DependencySpecification, parse_dependencies_yaml_content};
use crate::progress;
use anyhow::{Context, Result};
use gix::ObjectId;
use gix::progress::prodash::Progress;
use gix::progress::prodash::tree::Item;
use gix::refs::PartialNameRef;
use gix::worktree::state::checkout::Options;
use gix::{self};
use log::{debug, trace, warn};
use regex::Regex;
use semver::{Version, VersionReq};
use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet};
use std::env::{current_dir, home_dir};
use std::fmt;
use std::fmt::Display;
use std::fs::{create_dir_all, metadata, remove_dir_all, remove_file, set_permissions};
use std::hash::{Hash, Hasher};
use std::path::Path;
use std::path::PathBuf;
use std::time::Instant;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackageUrl {
    GitUrl(String),
    Root,
}

impl Display for PackageUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PackageUrl::GitUrl(url) => write!(f, "{}", url),
            PackageUrl::Root => write!(f, "Root Package"),
        }
    }
}

impl PackageUrl {
    pub fn as_str(&self) -> &str {
        match self {
            PackageUrl::GitUrl(url) => url.as_str(),
            PackageUrl::Root => "Root Package",
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        match self {
            PackageUrl::GitUrl(url) => url.as_bytes(),
            PackageUrl::Root => b"Root Package",
        }
    }
}

impl Hash for PackageUrl {
    fn hash<H: Hasher>(&self, state: &mut H) {
        normalize_url(self).hash(state)
    }
}

#[derive(Debug, Clone, Eq)]

// TODO: in the past the available versions were cached here
// This caused issues with reliably getting the version info updated when needed
// This could be re-introduced if this causes performance struggles.
pub struct GitPackage {
    pub url: PackageUrl,
    pub prefix: Option<String>,
    pub replacements: Option<Vec<[String; 2]>>,
}

impl Hash for GitPackage {
    fn hash<H: Hasher>(&self, state: &mut H) {
        normalize_url(&self.url).hash(state);
    }
}

impl PartialEq for GitPackage {
    fn eq(&self, other: &Self) -> bool {
        normalize_url(&self.url) == normalize_url(&other.url)
    }
}

impl GitPackage {
    pub fn new(
        url: PackageUrl,
        prefix: Option<String>,
        replacements: Option<Vec<[String; 2]>>,
    ) -> Self {
        GitPackage {
            url,
            prefix,
            replacements,
        }
    }

    /// Make sure the cached database exists and can actually be used, re-cloning it
    /// when the cached directory is the residue of an interrupted fetch: such a
    /// directory opens as a repository and even holds objects, but it has no
    /// references, so every later run fails on a sha upstream still has.
    pub fn ensure_usable_database(&self) -> anyhow::Result<()> {
        let path = self.get_database_path()?;

        if database_is_usable(&path) {
            return Ok(());
        }

        if path.exists() {
            remove_dir_all(&path)
                .context(format!("Failed to remove unusable database at {path:?}",))?;
        }

        self.clone_dependency_database()
    }

    pub fn get_database_path(&self) -> anyhow::Result<PathBuf> {
        let normalized = normalize_url(&self.url);

        // Hash the normalized url
        let mut hasher = DefaultHasher::new();
        normalized.hash(&mut hasher);
        let hash = format!("{:x}", hasher.finish());

        let home = home_dir().expect("Could not determine home directory");
        let path: PathBuf = home.join(".gipm").join("db").join(hash);
        Ok(path)
    }

    pub fn is_dirty(&self) -> anyhow::Result<bool> {
        let path = self.get_checkout_path()?;
        let repo = gix::open(&path)?;

        // A checkout that lost its own object store still opens, but HEAD no longer
        // resolves to a commit -- gix panics deeper inside `is_dirty` for that state,
        // so the absence is detected here and reported as an error naming the package
        // instead of aborting the run. Detached HEADs are fine: this asks whether HEAD
        // resolves, not whether it names a branch.
        if repo.head_commit().is_err() {
            return Err(anyhow::anyhow!(
                "Checkout for {} is damaged: its repository has no HEAD",
                self.name()
            ));
        }

        Ok(repo.is_dirty()?)
    }

    pub fn update_db(&mut self) -> anyhow::Result<()> {
        self.clone_dependency_database()?;
        Ok(())
    }

    pub fn name(&self) -> String {
        let normalized_url = normalize_url(&self.url);
        // Get the last path segment after '/' or '\'
        let repo_name = normalized_url
            .rsplit(&['/', '\\'][..])
            .next()
            .unwrap_or(&normalized_url);

        repo_name.to_string()
    }

    /// Fetch just the dependencies.yaml file from a specific version of a repository
    pub fn fetch_dependencies_yaml(
        &self,
        version: &Version,
    ) -> Result<Option<Vec<DependencySpecification>>> {
        let db_path = self.get_database_path()?;

        if !database_is_usable(&db_path) {
            // If database doesn't exist, we can't check for transitive deps. A database should always exist.

            // TODO: figure out where the clone should happen if we don't have a database.
            return Err(anyhow::anyhow!(
                "Database for dependency {} does not exist",
                self.name()
            ));
        }
        let db_repo = gix::open(&db_path)?;

        // Find the tag reference
        let tag_ref_name = format!(
            "refs/tags/{}",
            self.get_tag_name(version).ok_or(anyhow::anyhow!(
                "Version {version} not found in all_versions"
            ))?
        );
        let mut tag_ref = db_repo
            .find_reference(&tag_ref_name)
            .expect("Should have found a matching version");

        // Peel the tag to get the commit
        let target = tag_ref.peel_to_id()?;
        let commit = db_repo.find_object(target)?.peel_to_commit()?;

        // Get the tree from the commit
        let tree = commit.tree()?;

        // Look for dependencies.yaml in the root of the tree
        let deps_file_entry = match tree.lookup_entry_by_path("dependencies.yaml") {
            Ok(Some(entry)) => entry,
            _ => return Ok(None), // No dependencies.yaml file
        };

        // Get the blob content
        let blob = deps_file_entry.object()?.into_blob();
        let content = String::from_utf8(blob.data.to_vec())
            .context("Failed to decode dependencies.yaml content")?;

        // Parse the dependencies
        let transitive_deps = parse_dependencies_yaml_content(&content)?;
        Ok(Some(transitive_deps))
    }

    pub fn get_tag_name(&self, version: &Version) -> Option<String> {
        match self.get_available_versions() {
            Ok(v) => v.get(version).cloned(),
            Err(_) => None,
        }
    }

    pub fn get_commit_hash_for_version(&self, version: &Version) -> anyhow::Result<String> {
        let db_path = self.get_database_path()?;
        let db_repo = gix::open(&db_path)?;
        let tag_ref_name = format!(
            "refs/tags/{}",
            self.get_tag_name(version).ok_or(anyhow::anyhow!(
                "Version {version} not found in all_versions"
            ))?
        );
        let mut tag_ref = db_repo
            .find_reference(&tag_ref_name)
            .expect("Should have found a matching version");
        let target = tag_ref.peel_to_commit()?;
        Ok(target.id.to_string())
    }

    pub fn does_id_exist_in_db(&self, object: impl Into<ObjectId>) -> anyhow::Result<bool> {
        let db_path = self.get_database_path()?;
        if !database_is_usable(&db_path) {
            return Ok(false);
        }

        let object = object.into();

        let object_str = match &object {
            ObjectId::Sha1(id) => std::str::from_utf8(id)?,
            &_ => anyhow::bail!("Future - need to support for non-sha1 object ids"),
        };

        let db_repo = gix::open(&db_path)?;
        let exists = db_repo
            .try_find_object(object)
            .context(format!(
                "Failed to check if reference {object_str} exists in database for {}",
                self.name()
            ))?
            .is_some();
        Ok(exists)
    }

    pub fn does_ref_exist_in_db(&self, reference: &str) -> anyhow::Result<bool> {
        let db_path = self.get_database_path()?;
        if !database_is_usable(&db_path) {
            return Ok(false);
        }

        let db_repo = gix::open(&db_path)?;
        let exists = db_repo
            .try_find_reference(reference)
            .context(format!(
                "Failed to check if reference {} exists in database for {}",
                reference,
                self.name()
            ))?
            .is_some();
        Ok(exists)
    }

    pub fn get_checkout_path(&self) -> anyhow::Result<PathBuf> {
        match &self.url {
            PackageUrl::GitUrl(s) => {
                // Extract the repository name from the end of the URL and create a PathBuf: cwd/.gitvenv/<repo>

                // Remove trailing '/' if present
                let repo_url = s.trim_end_matches('/');
                // Get the last path segment after '/' or '\'
                let repo_url = repo_url.rsplit(&['/', '\\'][..]).next().unwrap_or(repo_url);
                // Remove .git suffix if present
                let repo_name = repo_url
                    .strip_suffix(".git")
                    .unwrap_or(repo_url)
                    .to_string();

                let cwd = current_dir()?;
                Ok(cwd.join(".gitvenv").join(repo_name))
            }
            PackageUrl::Root => unreachable!("Root package does not have a checkout path"),
        }
    }

    /// Get all available versions from a git package
    pub fn get_available_versions(&self) -> anyhow::Result<HashMap<Version, String>> {
        let db_path = self.get_database_path()?;

        if !database_is_usable(&db_path) {
            anyhow::bail!("Database for dependency {} does not exist", self.name());
        }

        let mut all_versions: HashMap<Version, String> = HashMap::new();

        let db_repo = gix::open(&db_path)?;
        let mut tag_names = Vec::new();

        // Extract tag names from the actual git repository
        let references = db_repo.references().expect("Failed to get references");
        let tag_refs = references
            .prefixed("refs/tags/")
            .expect("Failed to get tag references");
        for reference in tag_refs.flatten() {
            tag_names.push(reference.name().shorten().to_string());
        }

        // Regex: optional prefix, optional 'v', then semver (with ., -, or _ as separators)
        let semver_re = Regex::new(r"^(?P<prefix>.*?)(v)?(?P<major>\d+)[._-](?P<minor>\d+)[._-](?P<patch>\d+)(?:[._-]?(?P<rest>.*))?$")
            .unwrap();

        // Collect prefix statistics
        let mut prefix_counts = HashMap::new();
        let mut semver_tags = Vec::new();
        for tag in &tag_names {
            if let Some(caps) = semver_re.captures(tag) {
                let prefix = caps.name("prefix").map(|m| m.as_str()).unwrap_or("");
                *prefix_counts.entry(prefix.to_string()).or_insert(0) += 1;
                semver_tags.push((tag, prefix.to_string()));
            }
        }

        // Find the most common prefix (if any)
        let total = semver_tags.len();
        let (auto_prefix, _count) = prefix_counts
            .iter()
            .max_by_key(|(_, v)| *v)
            .map(|(k, v)| (k.clone(), *v))
            .unwrap_or((String::new(), 0));
        let use_auto_prefix = total > 0 && _count * 100 / total >= 75;

        // Use user-specified prefix, else auto-detected
        let effective_prefix = self.prefix.as_deref().filter(|s| !s.is_empty()).or({
            if use_auto_prefix && !auto_prefix.is_empty() {
                Some(auto_prefix.as_str())
            } else {
                None
            }
        });

        // Extract versions using the effective prefix
        for tag in &tag_names {
            if let Some(version) =
                Self::extract_version_from_tag(tag, effective_prefix, &self.replacements)
            {
                trace!("Extracted version {version} from tag {tag}");
                all_versions.insert(version, tag.to_string());
            } else {
                trace!("Failed to extract version from tag: {tag}");
            }
        }

        Ok(all_versions)
    }

    /// Extract version from a tag name, using flexible separators and optional v prefix
    fn extract_version_from_tag(
        tag: &str,
        prefix: Option<&str>,
        replacement: &Option<Vec<[String; 2]>>,
    ) -> Option<Version> {
        // Remove prefix if present
        let tag = if let Some(prefix) = prefix {
            if tag
                .to_ascii_lowercase()
                .starts_with(&prefix.to_ascii_lowercase())
            {
                &tag[prefix.len()..]
            } else {
                return None;
            }
        } else {
            tag
        };

        // Remove leading 'v' if present
        let mut tag = tag.strip_prefix('v').unwrap_or(tag).to_string();

        // Optionally apply replacement (for legacy cases)
        if let Some(replacement) = replacement {
            for [from, to] in replacement {
                tag = tag.replace(from, to);
            }
        }

        // Try to parse as semver directly
        match Version::parse(&tag) {
            Ok(ver) => {
                // Ignore versions with pre-release or build metadata (only accept stable versions)
                if ver.pre.is_empty() && ver.build.is_empty() {
                    Some(ver)
                } else {
                    None
                }
            }
            Err(_) => None,
        }
    }

    /// Parse version requirement with prefix and replacement handling
    pub fn parse_version_requirement(
        &self,
        version_req: &str,
        prefix: &Option<String>,
        replacement: &Option<Vec<[String; 2]>>,
    ) -> Result<VersionReq> {
        // Remove prefix if present
        let mut processed_req = if let Some(prefix) = prefix {
            version_req
                .strip_prefix(prefix)
                .unwrap_or(version_req)
                .to_string()
        } else {
            version_req.to_string()
        };

        // Apply replacements if specified
        if let Some(replacement) = replacement {
            for [from, to] in replacement {
                processed_req = processed_req.replace(from, to);
            }
        }

        // `==1.2.13` is how most people write an exact match; semver's grammar takes a
        // single `=`, so fold the doubled operator before parsing rather than rejecting
        // it outright.
        let processed_req: String = if processed_req.starts_with("==") {
            let cut: usize = 1;
            processed_req[cut..].to_string()
        } else {
            processed_req
        };

        // Try to parse as semver, if it fails, try to parse as exact version
        match semver::VersionReq::parse(&processed_req) {
            Ok(req) => Ok(req),
            Err(_) => VersionReq::parse(&format!("={processed_req}")).context(format!(
                "Failed to parse version requirement: {processed_req}"
            )),
        }
    }

    // Function which checks for the existence of or clones a git repository into /home/gipm/src/dependencies/name/version
    pub fn clone_dependency_database(&self) -> anyhow::Result<()> {
        // Get the user's home directory
        let path = self.get_database_path().expect("Could not get db path");
        debug!("Database path for {}: {:?}", self.name(), path);

        if let Ok(repo) = gix::open(&path)
            && database_is_usable(&path)
        {
            debug!("Found existing database at {path:?}");
            // Open existing repository and fetch updates
            let remote = repo
                .find_fetch_remote(Some("origin".into()))
                .expect("Failed to find fetch remote")
                .with_fetch_tags(gix::remote::fetch::Tags::All);

            let start = Instant::now();

            let mut update_progress_overall = progress::child(format!("{} db fetch", self.name()));

            let mut sub_progress_fetch = update_progress_overall.add_child("fetch".to_string());

            let prep = remote
                .connect(gix::remote::Direction::Fetch)?
                .prepare_fetch(&mut sub_progress_fetch, Default::default())?;

            let recv = prep.receive(&mut sub_progress_fetch, &gix::interrupt::IS_INTERRUPTED);

            // explicitly drop the sub-progress since we're done with it, to keep progress bars clean
            drop(sub_progress_fetch);

            match recv {
                Ok(_) => {
                    let stop = Instant::now();
                    update_progress_overall.done(format!(
                        "Completed in {:.02} seconds",
                        (stop - start).as_secs_f32()
                    ));
                }
                Err(e) => {
                    update_progress_overall.fail(format!("Failed to update {}: {e}", self.name(),));
                    anyhow::bail!("Failed to update database for {}: {e}", self.name());
                }
            }

            drop(update_progress_overall);

            Ok(())
        } else {
            // A directory that opens but carries no references is the residue of an
            // interrupted clone; it has to go before the re-clone, or the next run
            // inherits the same half-written database.
            if path.exists() {
                remove_dir_all(&path).expect("Failed to remove unusable database directory");
            }

            // First make the directory
            create_dir_all(&path).expect("Failed to create database clone directory");
            let url = gix::url::parse(self.url.as_str()).expect("Failed to parse URL");

            let start = Instant::now();

            let mut clone_progress_overall = progress::child(format!("{} db clone", self.name()));

            clone_progress_overall.init(Some(1), gix::progress::count("actions"));

            let mut bare_clone_progress =
                clone_progress_overall.add_child("Cloning dependency database");

            let mut prepare_clone =
                gix::prepare_clone_bare(url, &path).expect("Failed to prepare clone");
            let checkout_repo =
                prepare_clone.fetch_only(&mut bare_clone_progress, &gix::interrupt::IS_INTERRUPTED);

            clone_progress_overall.inc();

            let stop = Instant::now();
            match &checkout_repo {
                Ok(_) => {
                    clone_progress_overall.done(format!(
                        "Completed in {:.02} seconds",
                        (stop - start).as_secs_f32()
                    ));
                }
                Err(e) => {
                    clone_progress_overall.fail(format!(
                        "Dependency database for {} failed to clone: {e}",
                        self.name(),
                    ));
                }
            }

            drop(clone_progress_overall);
            // TODO: handle IO errors here with retry?
            match &checkout_repo {
                Ok(_) => Ok(()),
                Err(e) => Err(anyhow::anyhow!("Database clone failed: {e}")),
            }
        }
    }

    fn fetch_tag_from_db(&self, tag_name: &str, sub_progress: &mut Item) -> anyhow::Result<()> {
        // Set the remote URL to the database directory
        let checkout_dir = self.get_checkout_path()?;
        let bare_db_path = self.get_database_path()?;
        let mut checkout_repo = gix::open(&checkout_dir)
            .context(format!("Failed to open repository at {checkout_dir:?}"))?;
        let mut config = checkout_repo.config_snapshot_mut();
        config
            .set_raw_value(
                "remote.origin.url",
                bare_db_path.to_str().unwrap().as_bytes(),
            )
            .expect("Failed to set remote URL");
        config.commit().expect("Failed to commit config");

        // Check if the repository is dirty (has uncommitted changes)
        // We'll use a simple approach to check for uncommitted changes
        let dirty = checkout_repo.is_dirty()?;
        if dirty {
            warn!("Repository at {checkout_dir:?} has uncommitted changes, proceeding anyway");
        }

        let mut remote = checkout_repo
            .find_fetch_remote(Some("origin".into()))
            .expect("Failed to find fetch remote")
            .with_fetch_tags(gix::remote::fetch::Tags::None);

        // Clear existing refspecs and add only the specific tag we want
        remote.replace_refspecs(
            [format!("refs/tags/{tag_name}:refs/tags/{tag_name}").as_str()],
            gix::remote::Direction::Fetch,
        )?;

        let mut sub_progress_fetch =
            sub_progress.add_child(format!("fetching {checkout_dir:?} tag {tag_name}"));

        let start = Instant::now();

        let prep = remote
            .connect(gix::remote::Direction::Fetch)?
            .prepare_fetch(&mut sub_progress_fetch, Default::default())?
            .with_shallow(gix::remote::fetch::Shallow::DepthAtRemote(
                std::num::NonZero::new(1).unwrap(),
            ))
            .with_write_packed_refs_only(true);

        let recv = prep.receive(&mut sub_progress_fetch, &gix::interrupt::IS_INTERRUPTED);

        let stop = Instant::now();

        match recv {
            Ok(_) => {
                sub_progress_fetch.done(format!(
                    "Fetched {} tag {tag_name} in {:.02} seconds",
                    self.name(),
                    (stop - start).as_secs_f32()
                ));
                Ok(())
            }
            Err(e) => {
                sub_progress_fetch.fail(format!(
                    "Failed to fetch tag {tag_name} for {}: {e}",
                    self.name()
                ));
                anyhow::bail!("Failed to fetch tag {tag_name} for {}: {e}", self.name())
            }
        }
    }

    fn fetch_ref_from_db(
        &self,
        object: impl Into<ObjectId>,
        sub_progress: &mut Item,
    ) -> anyhow::Result<()> {
        // Set the remote URL to the database directory
        let checkout_dir = self.get_checkout_path()?;
        let bare_db_path = self.get_database_path()?;
        let mut checkout_repo = gix::open(&checkout_dir)
            .context(format!("Failed to open repository at {checkout_dir:?}"))?;
        let mut config = checkout_repo.config_snapshot_mut();
        config
            .set_raw_value(
                "remote.origin.url",
                bare_db_path.to_str().unwrap().as_bytes(),
            )
            .expect("Failed to set remote URL");
        config.commit().expect("Failed to commit config");

        // Check if the repository is dirty (has uncommitted changes)
        // We'll use a simple approach to check for uncommitted changes
        let dirty = checkout_repo.is_dirty()?;
        if dirty {
            warn!("Repository at {checkout_dir:?} has uncommitted changes, proceeding anyway");
        }

        let mut remote = checkout_repo
            .find_fetch_remote(Some("origin".into()))
            .expect("Failed to find fetch remote")
            .with_fetch_tags(gix::remote::fetch::Tags::None);

        let object: ObjectId = object.into();

        let ref_name = object.to_string().clone();

        // Clear existing refspecs and add only the specific tag we want
        remote.replace_refspecs([ref_name.as_bytes()], gix::remote::Direction::Fetch)?;

        let mut sub_progress_fetch =
            sub_progress.add_child(format!("fetching {checkout_dir:?} ref {object}"));

        let start = Instant::now();

        let prep = remote
            .connect(gix::remote::Direction::Fetch)?
            .prepare_fetch(&mut sub_progress_fetch, Default::default())?
            .with_shallow(gix::remote::fetch::Shallow::DepthAtRemote(
                std::num::NonZero::new(1).unwrap(),
            ))
            .with_write_packed_refs_only(true);

        let recv = prep.receive(&mut sub_progress_fetch, &gix::interrupt::IS_INTERRUPTED);

        let stop = Instant::now();

        match recv {
            Ok(_) => {
                sub_progress_fetch.done(format!(
                    "Fetched {} ref {object} in {:.02} seconds",
                    self.name(),
                    (stop - start).as_secs_f32()
                ));
                Ok(())
            }
            Err(e) => {
                sub_progress_fetch.fail(format!(
                    "Failed to fetch tag {object} for {}: {e}",
                    self.name()
                ));
                anyhow::bail!("Failed to fetch tag {object} for {}: {e}", self.name())
            }
        }
    }

    pub fn checkout_or_clone_object_from_database(
        &self,
        object: impl Into<ObjectId>,
        progress: &mut Item,
    ) -> anyhow::Result<()> {
        let checkout_dir = self.get_checkout_path()?;

        // Check if the repository already exists, which it shouldn't if we're cloning
        match gix::open(&checkout_dir) {
            Ok(_) => self.checkout_object_from_database(object, progress),
            Err(_) => self.clone_with_object_from_database(object, progress),
        }
    }

    pub fn clone_with_object_from_database(
        &self,
        object: impl Into<ObjectId>,
        sub_progress: &mut Item,
    ) -> anyhow::Result<()> {
        self.clone_object_into(&self.get_checkout_path()?, object, sub_progress)
    }

    /// Clone `object` out of the package database into an explicit destination
    /// directory rather than the package's `.gitvenv` entry. A submodule is a
    /// package that lives somewhere other than `.gitvenv/<name>` -- its mount
    /// point comes from the parent's index -- so this is the only place the
    /// destination is not implied by the package itself.
    pub fn clone_object_into(
        &self,
        dest: &PathBuf,
        object: impl Into<ObjectId>,
        sub_progress: &mut Item,
    ) -> anyhow::Result<()> {
        // Check if the repository already exists, which it shouldn't if we're cloning
        let checkout_dir = dest;
        let bare_db_path = self.get_database_path()?;
        let object: ObjectId = object.into();
        if gix::open(checkout_dir).is_ok() {
            anyhow::bail!(
                "Repository already exists at {} - should call checkout, not clone",
                self.get_checkout_path()?.display()
            )
        }

        if !&checkout_dir.exists() {
            create_dir_all(checkout_dir).context(format!(
                "Failed to create checkout directory: {checkout_dir:?}"
            ))?;
        }

        // TODO: This could be made more efficient for syncs by only cloning the one ref we need to the database repo
        self.ensure_usable_database()?;
        let db_repo = gix::open(&bare_db_path)?;

        // Check if the object exists in the database
        if db_repo.try_find_object(object)?.is_none() {
            return Err(anyhow::anyhow!(
                "Object {object} does not exist in the database for {}",
                self.name()
            ));
        }

        let ref_name = object.to_string().clone();

        // It seems like we'll have to first clone, then fetch again and checkout the desired commit.
        // TODO: This seems like it can be improved. can we not just clone the object directly?
        // Alternatively we could search the db for a ref that matches the object id, which we expect there should be most of the time
        let mut prepare_clone = gix::prepare_clone(
            bare_db_path.to_str().expect("Failed to get bare db path"),
            checkout_dir,
        )
        .expect("Failed to prepare clone")
        .with_shallow(gix::remote::fetch::Shallow::DepthAtRemote(
            std::num::NonZero::new(1).unwrap(),
        ))
        .configure_remote({
            move |mut r| {
                r = r.with_fetch_tags(gix::remote::fetch::Tags::None);
                r.replace_refspecs([ref_name.as_bytes()], gix::remote::Direction::Fetch)
                    .expect("Failed to set refspecs");
                Ok(r)
            }
        });

        let mut sub_progress_checkout_overall =
            sub_progress.add_child(format!("Cloning {} at object {object}", self.name()));

        let start_overall = Instant::now();

        sub_progress_checkout_overall.init(Some(2), gix::progress::count("actions"));

        let mut sub_progress_fetch = sub_progress.add_child(format!(
            "Fetching {checkout_dir:?} sha {object} from database {}",
            bare_db_path.display()
        ));

        // Perform a fetch and checkout
        let (mut prepare, _outcome) = prepare_clone
            .fetch_then_checkout(&mut sub_progress_fetch, &gix::interrupt::IS_INTERRUPTED)
            .expect("Fetch failed");

        drop(sub_progress_fetch);

        sub_progress_checkout_overall.inc();

        let (_repo, _outcome) = prepare
            .main_worktree(
                &mut sub_progress_checkout_overall,
                &gix::interrupt::IS_INTERRUPTED,
            )
            .context("Failed to checkout")?;

        let checkout_result =
            self.checkout_object_at(dest.clone(), object, &mut sub_progress_checkout_overall);

        sub_progress_checkout_overall.inc();

        update_submodules(
            checkout_dir,
            self.name(),
            &self.url,
            Some(&mut sub_progress_checkout_overall),
        )
        .context("submodule update failed")?;

        let stop = Instant::now();

        match checkout_result {
            Ok(_) => {
                sub_progress_checkout_overall.done(format!(
                    "Cloned {} at object {object} in {:.02} seconds",
                    self.name(),
                    (stop - start_overall).as_secs_f32()
                ));
            }
            Err(e) => {
                sub_progress_checkout_overall.fail(format!(
                    "Failed to clone {} at object {object}: {e}",
                    self.name()
                ));
                return Err(e);
            }
        }

        drop(sub_progress_checkout_overall);

        // Update the remote.origin.url in the .git/config to the original url we used to clone the database
        // This facilitates the use of the database as a normal git repository if desired
        let mut f = gix::config::File::from_git_dir(checkout_dir.join(".git").clone())
            .context("Failed to open config file")?;
        f.set_existing_raw_value("remote.origin.url", self.url.as_bytes())
            .context("Failed to write remote.origin.url")?;
        let mut file = std::fs::File::create(checkout_dir.join(".git").join("config"))
            .context("Failed to create config file")?;
        f.write_to_filter(&mut file, |s| s.meta().source == gix::config::Source::Local)
            .context("Failed to write config file")?;

        Ok(())
    }

    pub fn checkout_object_from_database(
        &self,
        object: impl Into<ObjectId>,
        sub_progress: &mut Item,
    ) -> anyhow::Result<()> {
        self.checkout_object_at(self.get_checkout_path()?, object.into(), sub_progress)
    }

    /// `checkout_object_from_database` for an explicit checkout directory. A submodule
    /// is mounted below its parent (`.gitvenv/parent/child`), which is *not* the path
    /// `get_checkout_path` would derive from its url (`.gitvenv/child`), so every path
    /// that can reach a submodule has to thread the destination through instead of
    /// recomputing it.
    fn checkout_object_at(
        &self,
        dest: PathBuf,
        object: impl Into<ObjectId>,
        sub_progress: &mut Item,
    ) -> anyhow::Result<()> {
        let checkout_repo = gix::open(&dest)?;
        let object = object.into();
        // `try_find_object` rather than `find_object` and a match on the error: the
        // error enum that carried `NotFound` was folded into a composed error type
        // upstream, so the absence of an object is only an option here.
        let commit = match checkout_repo.try_find_object(object)? {
            Some(object) => object.peel_to_commit()?,
            None => {
                // Fetch the object first
                self.fetch_ref_from_db(object, sub_progress)?;
                match checkout_repo.try_find_object(object)? {
                    Some(object) => object.peel_to_commit()?,
                    None => anyhow::bail!(
                        "Object {object} is still missing from repository {} after fetching from the database",
                        self.name(),
                    ),
                }
            }
        };

        let mut sub_progress_checkout =
            sub_progress.add_child(format!("Checking out {} id {}", self.name(), object));

        if let Ok(Some(t)) = checkout_repo.try_find_object(object)
            && let Ok(head) = checkout_repo.head()
            && let Ok(head_id) = head.into_peeled_id()
            && t.id == head_id
        {
            let subs = checkout_repo.submodules()?;
            let names: Vec<String> = match subs {
                None => vec![],
                Some(list) => list
                    .map(|s| format!("{}", s.name()))
                    .collect::<Vec<String>>(),
            };

            if !names.is_empty() {
                sub_progress_checkout.info("updating submodules".to_string());

                // Update the HEAD reference to point to the correct tag ref
                // TODO handle this in one common place
                let update = gix::refs::transaction::Change::Update {
                    log: Default::default(),
                    expected: gix::refs::transaction::PreviousValue::Any,
                    new: commit.id.into(),
                };

                checkout_repo.edit_reference(gix::refs::transaction::RefEdit {
                    change: update,
                    name: "HEAD".try_into().expect("valid"),
                    deref: false,
                })?;

                update_submodules(
                    checkout_repo.workdir().expect("should have a workdir"),
                    self.name(),
                    &self.url,
                    Some(&mut sub_progress_checkout),
                )
                .context("submodule update failed")?;
            };
            sub_progress_checkout.done(format!("{} already checked out at {object}", self.name()));
            drop(sub_progress_checkout);
            return Ok(());
        }

        // Perform the checkout using gix-worktree-state

        // Get the current index to track files before checkout
        let tracked_before: Option<HashSet<String>> = match checkout_repo.index() {
            Ok(index) => Some(
                index
                    .entries()
                    .iter()
                    .map(|entry| entry.path(&index).to_string())
                    .collect(),
            ),
            Err(_) => None,
        };

        // Create index from the commit's tree
        let tree = commit.tree()?;
        let state =
            gix::index::State::from_tree(&tree.id, &checkout_repo.objects, Default::default())?;
        let mut index = gix::index::File::from_state(state, checkout_repo.index_path());

        // Options now carry the repository's filter pipeline, so they are built rather
        // than written out; both flags below were left at their default false.
        let (pipeline, _pipeline_index) = checkout_repo.filter_pipeline(None)?;
        let opts = Options::new(pipeline.into_parts().0);

        let files = sub_progress_checkout.add_child_with_id(
            "checkout commit".to_string(),
            gix::clone::checkout::main_worktree::ProgressId::CheckoutFiles.into(),
        );
        let bytes = sub_progress_checkout.add_child_with_id(
            "write files".to_string(),
            gix::clone::checkout::main_worktree::ProgressId::BytesWritten.into(),
        );

        files.init(Some(index.entries().len()), gix::progress::count("files"));
        bytes.init(None, gix::progress::bytes());

        let start = Instant::now();
        // Perform the checkout
        gix::worktree::state::checkout(
            &mut index,
            checkout_repo.workdir().unwrap(),
            checkout_repo.objects.clone().into_arc()?,
            &files,
            &bytes,
            &gix::interrupt::IS_INTERRUPTED,
            opts,
        )?;

        files.show_throughput(start);
        bytes.show_throughput(start);

        drop(files);
        drop(bytes);

        let stop: Instant = Instant::now();
        sub_progress_checkout.done(format!(
            "Complete in {:.02} seconds",
            (stop - start).as_secs_f32()
        ));

        drop(sub_progress_checkout);

        // Write the updated index
        index.write(Default::default())?;

        // Get the new index to track files after checkout
        if tracked_before.is_some() {
            let new_index = checkout_repo.index()?;
            let tracked_after: HashSet<String> = new_index
                .entries()
                .iter()
                .map(|entry| entry.path(&new_index).to_string())
                .collect();

            // Find files that were tracked before but are not tracked after
            let files_to_remove: Vec<String> = if let Some(files) = tracked_before {
                files.difference(&tracked_after).cloned().collect()
            } else {
                Vec::new()
            };

            let remove_items = sub_progress.add_child_with_id(
                "Remove items".to_string(),
                gix::clone::checkout::main_worktree::ProgressId::CheckoutFiles.into(),
            );

            // Remove files that are no longer tracked
            let workdir = checkout_repo.workdir().unwrap();
            for file_path in files_to_remove {
                let full_path = workdir.join(&file_path);
                if full_path.exists() {
                    if full_path.is_file() {
                        remove_file(&full_path)?;
                        remove_items.inc();
                        debug!("Removed file: {file_path}");
                    } else if full_path.is_dir() {
                        remove_dir_all(&full_path)?;
                        remove_items.inc();
                        debug!("Removed directory: {file_path}");
                    }
                }
            }

            remove_items.done(format!(
                "Complete ({} items)",
                remove_items.step().unwrap_or(0),
            ));
            drop(remove_items);

            let fix_permissions = sub_progress.add_child_with_id(
                "Update permissions".to_string(),
                gix::clone::checkout::main_worktree::ProgressId::CheckoutFiles.into(),
            );

            // Check and fix file modes for tracked files
            for entry in new_index.entries() {
                let file_path = entry.path(&new_index).to_string();
                let full_path = workdir.join(&file_path);

                // TODO
                if entry.mode == gix::index::entry::Mode::COMMIT {
                    // Skip submodule for now
                    continue;
                }

                if full_path.exists() {
                    let metadata = metadata(&full_path)?;
                    let expected_mode = entry.mode.bits();

                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let current_mode = metadata.permissions().mode();

                        // Normalize modes for comparison
                        // Git stores modes as 100644, 100755, etc. (with type bits)
                        // Filesystem modes are typically 0644, 0755, etc. (without type bits)
                        let normalized_current = current_mode & 0o7777; // Remove type bits, keep permissions
                        let normalized_expected = expected_mode & 0o7777; // Remove type bits, keep permissions

                        if normalized_current != normalized_expected {
                            let mut permissions = metadata.permissions();
                            // Preserve the file type bits from current mode, apply expected permissions
                            let new_mode = (current_mode & 0o170000) | normalized_expected;
                            permissions.set_mode(new_mode);
                            set_permissions(&full_path, permissions)?;

                            let current_str = format!("{normalized_current:o}");
                            let expected_str = format!("{normalized_expected:o}");
                            debug!(
                                "Updated permissions for {file_path}: {current_str} -> {expected_str}"
                            );
                            fix_permissions.inc();
                        }
                    }

                    #[cfg(windows)]
                    {
                        // On Windows, only the readonly attribute is relevant for permissions.
                        // Git's 100755 means executable, which on Windows is not tracked.
                        // We can only set or unset readonly for 100644 (not executable) vs 100755 (executable).
                        // 0100 (owner execute) is the relevant bit for executability.
                        let is_executable = (expected_mode & 0o111) != 0;
                        let mut permissions = metadata.permissions();
                        let readonly = permissions.readonly();

                        // If the file should be executable, ensure it's not readonly.
                        // If the file should not be executable, set readonly (best effort).
                        // This is a lossy mapping, but it's the best we can do on Windows.
                        if is_executable && readonly {
                            // Deliberate: `set_readonly(false)` is the cross-platform way to undo
                            // readonly here; the mode we want is already implied by `expected_mode`,
                            // and rewriting it with `PermissionsExt` would change checkout behaviour
                            // on Windows.
                            #[allow(clippy::permissions_set_readonly_false)]
                            permissions.set_readonly(false);
                            set_permissions(&full_path, permissions)?;
                            debug!(
                                "Updated permissions for {file_path}: readonly -> writable (executable)"
                            );
                            fix_permissions.inc();
                        } else if !is_executable && !readonly {
                            permissions.set_readonly(true);
                            set_permissions(&full_path, permissions)?;
                            debug!(
                                "Updated permissions for {file_path}: writable -> readonly (not executable)"
                            );
                            fix_permissions.inc();
                        }
                    }
                }
            }

            fix_permissions.done(format!(
                "Complete ({} items)",
                fix_permissions.step().unwrap_or(0),
            ));

            drop(fix_permissions);
        }

        index
            .write(Default::default())
            .expect("Failed to write index");

        // Update the HEAD reference to point to the correct tag ref
        // TODO handle this in one common place
        let update = gix::refs::transaction::Change::Update {
            log: Default::default(),
            expected: gix::refs::transaction::PreviousValue::Any,
            new: commit.id.into(),
        };

        checkout_repo.edit_reference(gix::refs::transaction::RefEdit {
            change: update,
            name: "HEAD".try_into().expect("valid"),
            deref: false,
        })?;

        // Update submodules if any
        let subs = checkout_repo.submodules()?;
        let names: Vec<String> = match subs {
            None => vec![],
            Some(list) => list
                .map(|s| format!("{}", s.name()))
                .collect::<Vec<String>>(),
        };

        if !names.is_empty() {
            update_submodules(
                checkout_repo.workdir().expect("should have a workdir"),
                self.name(),
                &self.url,
                Some(sub_progress),
            )
            .context("submodule update failed")?;
        };

        Ok(())
    }

    pub fn checkout_from_database(&self, version: &Version) -> anyhow::Result<()> {
        // Path to the bare database repository
        let bare_db_path = self.get_database_path()?;
        if !database_is_usable(&bare_db_path) {
            anyhow::bail!("Database for does not exist at {:?}", bare_db_path);
        }

        let start_overall = Instant::now();

        let tag_name = self.get_tag_name(version).ok_or(anyhow::anyhow!(
            "Version {version} not found in all_versions"
        ))?;

        // Handle existing checkout directory
        let checkout_dir = self.get_checkout_path()?;

        let mut sub_progress_checkout_overall = progress::child(self.name());

        if checkout_dir.exists() {
            // Check if it's a git repository
            match gix::open(&checkout_dir) {
                Ok(checkout_repo) => {
                    debug!("Found existing git repository at {checkout_dir:?}");

                    if let Ok(Some(t)) = checkout_repo.try_find_reference(&tag_name)
                        && let Ok(tag_id) = t.into_fully_peeled_id()
                        && let Ok(head) = checkout_repo.head()
                        && let Ok(head_id) = head.into_peeled_id()
                        && tag_id == head_id
                    {
                        sub_progress_checkout_overall.done(format!(
                            "{} already checked out at tag {tag_name}",
                            self.name(),
                        ));
                        drop(sub_progress_checkout_overall);
                        return Ok(());
                    }

                    self.fetch_tag_from_db(&tag_name, &mut sub_progress_checkout_overall)
                        .context(format!(
                            "Failed to fetch tag {tag_name} for {}",
                            self.name()
                        ))?;

                    // After fetching, check out the tag into the worktree.
                    // This is similar to what PrepareCheckout::main_worktree does.
                    // 1. Find the tag reference
                    let tag_ref_name = format!("refs/tags/{tag_name}");
                    let mut tag_ref = checkout_repo
                        .find_reference(&tag_ref_name)
                        .context(format!("Could not find tag ref {tag_ref_name}"))?;

                    // 2. Peel the tag to the target object (usually a commit)
                    let target = tag_ref.peel_to_commit()?;

                    match self
                        .checkout_object_from_database(
                            target.id,
                            &mut sub_progress_checkout_overall,
                        )
                        .context(format!(
                            "Failed to checkout tag {tag_name} for {}",
                            self.name()
                        )) {
                        Ok(_) => {
                            // Update the HEAD reference to point to the correct tag ref
                            // TODO handle this in one common place
                            let update = gix::refs::transaction::Change::Update {
                                log: Default::default(),
                                expected: gix::refs::transaction::PreviousValue::Any,
                                new: target.id.into(),
                            };

                            checkout_repo.edit_reference(gix::refs::transaction::RefEdit {
                                change: update,
                                name: "HEAD".try_into().expect("valid"),
                                deref: false,
                            })?;

                            let stop_overall = Instant::now();

                            sub_progress_checkout_overall.done(format!(
                                "Checked out {version} in {:.02} seconds",
                                (stop_overall - start_overall).as_secs_f32(),
                            ));
                        }
                        Err(e) => {
                            sub_progress_checkout_overall.fail(format!(
                                "Failed to checkout tag {tag_name} for {}: {e}",
                                self.name()
                            ));
                            anyhow::bail!(
                                "Failed to checkout tag {tag_name} for {}: {e}",
                                self.name()
                            );
                        }
                    }
                }
                Err(_) => {
                    // Directory exists but is not a git repository
                    anyhow::bail!(
                        "Directory {checkout_dir:?} exists but is not a git repository. Please remove it manually or choose a different location."
                    );
                }
            }
        } else {
            // Create the checkout directory if it doesn't exist
            create_dir_all(&checkout_dir)?;

            // TODO - is this really necessary?
            let tag_name_for_closure = tag_name.clone();

            let name_ref = <&PartialNameRef>::try_from(&tag_name).expect("valid");

            let mut prepare_clone = gix::prepare_clone(
                bare_db_path.to_str().expect("Failed to get bare db path"),
                &checkout_dir,
            )
            .expect("Failed to prepare clone")
            .with_ref_name(Some(name_ref))
            .expect("Failed to parse ref name")
            .with_shallow(gix::remote::fetch::Shallow::DepthAtRemote(
                std::num::NonZero::new(1).unwrap(),
            ))
            .configure_remote({
                move |r| {
                    let mut r = r.with_fetch_tags(gix::remote::fetch::Tags::None);
                    // Only fetch the specific tag we need
                    r.replace_refspecs(
                        [format!(
                            "refs/tags/{tag_name_for_closure}:refs/tags/{tag_name_for_closure}"
                        )
                        .as_str()],
                        gix::remote::Direction::Fetch,
                    )?;
                    Ok(r)
                }
            });

            sub_progress_checkout_overall.init(Some(3), gix::progress::count("actions"));

            let mut sub_progress_fetch = sub_progress_checkout_overall.add_child(format!(
                "Fetching {checkout_dir:?} ref {name_ref:?} (tag {tag_name})"
            ));

            // Perform a bare clone (no checkout)
            let (mut prepare_checkout, _) = prepare_clone
                .fetch_then_checkout(&mut sub_progress_fetch, &gix::interrupt::IS_INTERRUPTED)
                .expect("Fetch failed");

            drop(sub_progress_fetch);

            sub_progress_checkout_overall.inc();

            let mut sub_progress_checkout = sub_progress_checkout_overall
                .add_child(format!("Checking out worktree for {checkout_dir:?}"));

            let (repo, _outcome) = prepare_checkout
                .main_worktree(&mut sub_progress_checkout, &gix::interrupt::IS_INTERRUPTED)
                .context("Failed to checkout")?;

            drop(sub_progress_checkout);

            sub_progress_checkout_overall.inc();

            // We checked out a symbolic ref, which we MIGHT need to resolve from a grafted and/or tag ref to the proper commit.
            // If we don't do this, the HEAD may mismatch the .lock file, leading to much confusion.

            // Furthermore, calling the checkout_object_from_database will handle submodule init.

            // 2. Peel the tag to the target object (usually a commit)
            let commit = repo
                .head_commit()
                .expect("Should have a HEAD, we just checked it out");

            match self
                .checkout_object_from_database(commit.id, &mut sub_progress_checkout_overall)
                .context(format!(
                    "Failed to checkout tag {tag_name} for {}",
                    self.name()
                )) {
                Ok(_) => {
                    // Update the HEAD reference to point to the correct tag ref
                    // TODO handle this in one common place
                    let update = gix::refs::transaction::Change::Update {
                        log: Default::default(),
                        expected: gix::refs::transaction::PreviousValue::Any,
                        new: commit.id.into(),
                    };

                    repo.edit_reference(gix::refs::transaction::RefEdit {
                        change: update,
                        name: "HEAD".try_into().expect("valid"),
                        deref: false,
                    })?;

                    let stop_overall = Instant::now();

                    sub_progress_checkout_overall.done(format!(
                        "Checked out {version} in {:.02} seconds",
                        (stop_overall - start_overall).as_secs_f32(),
                    ));
                }
                Err(e) => {
                    sub_progress_checkout_overall.fail(format!(
                        "Failed to checkout tag {tag_name} for {}: {e}",
                        self.name()
                    ));
                    anyhow::bail!("Failed to checkout tag {tag_name} for {}: {e}", self.name());
                }
            }
        }

        sub_progress_checkout_overall.inc();

        let stop = Instant::now();

        sub_progress_checkout_overall.done(format!(
            "Completed in {:.02} seconds",
            (stop - start_overall).as_secs_f32()
        ));

        drop(sub_progress_checkout_overall);

        // Update the remote.origin.url in the .git/config to the original url we used to clone the database
        // This facilitates the use of the database as a normal git repository if desired
        let mut f = gix::config::File::from_git_dir(checkout_dir.join(".git").clone())
            .context("Failed to open config file")?;
        f.set_existing_raw_value("remote.origin.url", self.url.as_bytes())
            .context("Failed to write remote.origin.url")?;
        let mut file = std::fs::File::create(checkout_dir.join(".git").join("config"))
            .context("Failed to create config file")?;
        f.write_to_filter(&mut file, |s| s.meta().source == gix::config::Source::Local)
            .context("Failed to write config file")?;

        Ok(())
    }
}

impl fmt::Display for GitPackage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Name: {}, URL: {}", self.name(), self.url)
    }
}

/// A cached database is only usable when it opens as a repository *and* at least
/// one of its references still resolves to an object we actually hold. An
/// interrupted fetch leaves a directory that opens happily but carries no refs,
/// or refs whose targets were never downloaded, and trusting either is what made
/// later runs report "Object ... does not exist in the database" for a sha that
/// upstream still publishes.
pub fn database_is_usable(path: &PathBuf) -> bool {
    let db_repo = match gix::open(path) {
        Err(_) => return false,
        Ok(db_repo) => db_repo,
    };

    let platform = match db_repo.references() {
        Err(_) => return false,
        Ok(platform) => platform,
    };

    let refs = match platform.all() {
        Err(_) => return false,
        Ok(refs) => refs,
    };

    for maybe_ref in refs {
        if let Ok(reference) = &maybe_ref
            && let Some(oid) = reference.target().try_id()
        {
            let object: gix::ObjectId = oid.into();
            if let Ok(Some(_)) = db_repo.try_find_object(object) {
                return true;
            }
        }
    }

    false
}

pub fn normalize_url(url: &PackageUrl) -> String {
    // Try to parse as a URL to handle userinfo (username:token@)
    // If parsing fails, fallback to manual normalization
    match &url {
        PackageUrl::GitUrl(s) => {
            if let Ok(parsed) = url::Url::parse(s) {
                // Remove username and password if present
                let mut normalized = String::new();
                // Scheme is ignored for hashing
                if let Some(host) = parsed.host_str() {
                    normalized.push_str(host);
                }
                if let Some(port) = parsed.port() {
                    normalized.push(':');
                    normalized.push_str(&port.to_string());
                }
                // Add path, removing trailing slashes and then a trailing .git --
                // order matters: `repo.git/` has to normalize the same as `repo.git`.
                // The suffix test is case-insensitive so `repo.GIT` folds too.
                let mut path = parsed.path().trim_end_matches('/').to_string();
                if path.len() >= 4 && path.to_ascii_lowercase().ends_with(".git") {
                    let cut: usize = path.len() - 4;
                    path = path[0..cut].to_string();
                }
                normalized.push_str(&path);
                // Lowercase for case-insensitivity
                return normalized.to_ascii_lowercase();
            }

            // Fallback: manual normalization for scp-like and other forms
            let s = s
                .trim_start_matches("https://")
                .trim_start_matches("http://")
                .trim_start_matches("ssh://")
                .trim_start_matches("git://")
                .trim_start_matches("git@");

            // Remove userinfo if present (username:token@)
            let s = if let Some(at_idx) = s.find('@') {
                &s[at_idx + 1..]
            } else {
                s
            };

            // For git@github.com:user/repo.git, convert ':' to '/'
            let s = if let Some(idx) = s.find(':') {
                // Only replace the first ':' after the host
                let (host, rest) = s.split_at(idx);
                let rest = &rest[1..]; // skip the ':'
                format!("{host}/{rest}")
            } else {
                s.to_string()
            };

            // Trim a trailing separator first, then the .git suffix, matching the
            // parsed branch above so both agree on one cache entry.
            let s = s.trim_end_matches('/');
            let s = if s.len() >= 4 && s.to_ascii_lowercase().ends_with(".git") {
                let cut: usize = s.len() - 4;
                &s[0..cut]
            } else {
                s
            };

            // Lowercase for case-insensitivity
            s.to_lowercase()
        }
        PackageUrl::Root => "ROOT".to_string(),
    }
}

/// Update the submodules of the repository checked out at `work_dir`, in-process.
///
/// A submodule is a package like any other: the commit it is pinned to is an
/// entry in the parent's index, its remote comes from `.gitmodules`, and it is
/// cloned out of the shared database through the same path a top-level
/// dependency takes. Recursion is therefore not done here -- `clone_object_into`
/// ends by calling this function, so the clone that owns a submodule brings in
/// that submodule's own submodules.
pub fn update_submodules(
    work_dir: &Path,
    pkg_name: String,
    parent_url: &PackageUrl,
    parent: Option<&mut Item>,
) -> anyhow::Result<usize> {
    let repo = gix::open(work_dir)?;

    let subs: Vec<gix::Submodule<'_>> = match repo.submodules()? {
        None => Vec::new(),
        Some(list) => list.collect(),
    };

    if subs.is_empty() {
        return Ok(0);
    }

    // Nested under the package bar when one is available, its own line otherwise: a
    // submodule download must never be a silent stretch of the run. The parameter is not
    // called `progress` so the `progress::child` fallback below can stay readable.
    let mut subprogress: Item = match parent {
        Some(item) => item.add_child("submodules".to_string()),
        None => progress::child(format!("{} submodules", pkg_name)),
    };

    subprogress.init(Some(subs.len()), gix::progress::count("submodules"));

    let mut updated: usize = 0;
    for sub in subs.iter() {
        let name: String = format!("{}", sub.name());

        // The pinned commit is an index entry, so it is known before anything is
        // downloaded; a submodule that carries no index entry has nothing to check
        // out and is left alone rather than guessed at.
        let pinned: ObjectId = match sub.index_id()? {
            None => {
                subprogress.info(format!(
                    "{} has no commit pinned in the parent index, leaving it alone",
                    name,
                ));
                continue;
            }
            Some(oid) => oid,
        };

        let url: String = resolve_submodule_url(format!("{}", sub.url()?), parent_url, work_dir);
        let dest: PathBuf = sub.work_dir()?;

        // A submodule already sitting at its pinned commit needs no download. The
        // clone path checks a tree out and then walks the submodule table again, so
        // one pass can arrive on a directory that already holds the repository --
        // `clone_object_into` refuses those on principle (it is a clone, not a
        // checkout), and refusing there would make the second pass an error.
        let already: bool = match gix::open(&dest) {
            Err(_) => false,
            Ok(existing) => match existing.head() {
                Err(_) => false,
                Ok(head) => match head.into_peeled_id() {
                    Err(_) => false,
                    Ok(id) => id == pinned,
                },
            },
        };

        if already {
            let item = subprogress.add_child(format!("{} already at {}", name, pinned));
            item.done(format!("{} submodule already at {}", name, pinned));
            drop(item);
            updated += 1;
            subprogress.inc();
            continue;
        }

        let dep = GitPackage::new(PackageUrl::GitUrl(url), Some(name.clone()), None);

        let mut item = subprogress.add_child(format!("{} clone", name));
        match dep
            .ensure_usable_database()
            .and_then(|_| dep.clone_object_into(&dest, pinned, &mut item))
        {
            Ok(_) => {
                item.done(format!("{} submodule at {}", name, pinned));
                updated += 1;
            }
            Err(e) => {
                item.fail(format!("Failed to update submodule {}: {e}", name));
                subprogress.fail(format!("Failed to update submodules: {e}"));
                drop(subprogress);
                return Err(e);
            }
        }

        drop(item);
        subprogress.inc();
    }

    subprogress.done(format!("{} submodules updated", updated));
    drop(subprogress);

    Ok(updated)
}

/// Resolve a submodule url the way `git` does: a url that carries no scheme is
/// relative to the parent's *remote*, not to its checkout directory, and only
/// the last path segment of that remote is dropped. A parent that is itself a
/// local path has no remote to lean on, so the checkout directory is used.
fn resolve_submodule_url(raw: String, parent_url: &PackageUrl, work_dir: &Path) -> String {
    let has_scheme: bool = raw.contains("://") || (raw.contains('@') && raw.contains(':'));
    if has_scheme {
        return raw;
    }

    let parent: String = parent_url.as_str().to_string();
    let base: String = match parent.rfind('/') {
        Some(idx) => parent[..idx].to_string(),
        None => "".to_string(),
    };

    if parent.contains("://") && !base.is_empty() {
        return format!("{}/{}", base, raw);
    }

    work_dir.join(raw).display().to_string()
}

#[cfg(test)]
#[test]
fn test_package_url_identity() -> anyhow::Result<()> {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let https: PackageUrl = PackageUrl::GitUrl("https://github.com/user/repo.git".to_string());
    let ssh: PackageUrl = PackageUrl::GitUrl("ssh://git@github.com/user/repo.git".to_string());
    let scp: PackageUrl = PackageUrl::GitUrl("git@github.com:user/repo.git".to_string());

    anyhow::ensure!(
        https.as_str() == "https://github.com/user/repo.git",
        "as_str must hand the url back verbatim, got {}",
        &https.as_str(),
    );
    anyhow::ensure!(
        https.as_bytes() == b"https://github.com/user/repo.git",
        "as_bytes must be as_str's bytes: {}",
        &https.as_str(),
    );
    anyhow::ensure!(
        PackageUrl::Root.as_str() == "Root Package",
        "the root package has no url, got {}",
        &PackageUrl::Root.as_str(),
    );
    anyhow::ensure!(
        PackageUrl::Root.as_bytes() == b"Root Package",
        "as_bytes must agree with as_str on the root package",
    );
    let https_shown: String = format!("{}", https.clone());
    anyhow::ensure!(
        https_shown == https.as_str(),
        "Display must print the url verbatim, got {https_shown}",
    );
    let root_shown: String = format!("{}", PackageUrl::Root);
    anyhow::ensure!(
        root_shown == "Root Package",
        "Display must name the root package, got {root_shown}",
    );

    let hash_of = |url: PackageUrl| -> u64 {
        let mut hasher: DefaultHasher = DefaultHasher::new();
        url.hash(&mut hasher);
        hasher.finish()
    };

    let https_hash: u64 = hash_of(https.clone());
    anyhow::ensure!(
        https_hash == hash_of(ssh.clone()) && hash_of(ssh.clone()) == hash_of(scp.clone()),
        "https/ssh/scp spellings of one repo must hash alike: {:x} {:x} {:x}",
        https_hash,
        hash_of(ssh.clone()),
        hash_of(scp.clone()),
    );
    anyhow::ensure!(
        https_hash != hash_of(PackageUrl::Root),
        "the root package must not collide with a real url",
    );

    Ok(())
}

#[cfg(test)]
#[test]
fn test_git_package_identity() -> anyhow::Result<()> {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let https: GitPackage = GitPackage::new(
        PackageUrl::GitUrl("https://github.com/user/repo.git".to_string()),
        None,
        None,
    );
    let tokened: GitPackage = GitPackage::new(
        PackageUrl::GitUrl("https://user:sekret@github.com/user/repo.git".to_string()),
        Some("v".to_string()),
        None,
    );
    let other: GitPackage = GitPackage::new(
        PackageUrl::GitUrl("git@github.com:user/other.git".to_string()),
        None,
        None,
    );

    anyhow::ensure!(
        https == tokened,
        "prefix/replacement are not identity: a userinfo-carrying url is the same package",
    );
    anyhow::ensure!(
        !(https == other),
        "different repositories must not compare equal",
    );

    let hash_of = |pkg: GitPackage| -> u64 {
        let mut hasher: DefaultHasher = DefaultHasher::new();
        pkg.hash(&mut hasher);
        hasher.finish()
    };

    let https_hash: u64 = hash_of(https.clone());
    anyhow::ensure!(
        https_hash == hash_of(tokened.clone()),
        "Hash must agree with PartialEq: {:x} vs {:x}",
        https_hash,
        hash_of(tokened.clone()),
    );
    anyhow::ensure!(
        https_hash != hash_of(other.clone()),
        "Hash must not collapse distinct repositories",
    );

    Ok(())
}

#[cfg(test)]
#[test]
fn test_normalize_url_forms() -> anyhow::Result<()> {
    let of = |s: &str| -> String { normalize_url(&PackageUrl::GitUrl(s.to_string())) };

    anyhow::ensure!(
        of("https://github.com/user/repo.git") == "github.com/user/repo",
        "the .git suffix and the scheme must not survive normalization",
    );
    anyhow::ensure!(
        of("https://user:sekret@github.com/user/repo.git") == "github.com/user/repo",
        "userinfo must not split one repository into two cache entries: {}",
        of("https://user:sekret@github.com/user/repo.git"),
    );
    anyhow::ensure!(
        of("ssh://git@github.com/user/repo.git") == "github.com/user/repo",
        "ssh must agree with https",
    );
    // The `.git` strip is case-insensitive and runs after the trailing-slash trim,
    // so an upper-case suffix and a trailing separator both fold into the same entry.
    anyhow::ensure!(
        of("HTTPS://GITHUB.COM/USER/REPO.GIT") == "github.com/user/repo",
        "case-insensitivity must cover the .git suffix: {}",
        of("HTTPS://GITHUB.COM/USER/REPO.GIT"),
    );
    anyhow::ensure!(
        of("https://github.com/user/repo/") == "github.com/user/repo",
        "a trailing slash must not create a second cache entry",
    );
    anyhow::ensure!(
        of("https://example.com:8080/user/repo.git") == "example.com:8080/user/repo",
        "a non-default port is a different remote and must stay distinct",
    );
    anyhow::ensure!(
        of("file:///home/gipm/tests/update/fixtures/alpha.git")
            == "/home/gipm/tests/update/fixtures/alpha",
        "a file:// remote keeps its path (there is no host to fold in): {}",
        of("file:///home/gipm/tests/update/fixtures/alpha.git"),
    );

    anyhow::ensure!(
        of("git@github.com:user/repo.git") == "github.com/user/repo",
        "the scp-like form is not parseable as a URL and must go through the fallback: {}",
        of("git@github.com:user/repo.git"),
    );
    // The fallback trims the trailing slash before stripping `.git`, so a trailing
    // separator cannot leave the suffix behind -- it must agree with the parsed
    // branch above.
    anyhow::ensure!(
        of("git@github.com:user/repo.git/") == "github.com/user/repo",
        "the fallback must fold a trailing separator the same way the parser does: {}",
        of("git@github.com:user/repo.git/"),
    );

    anyhow::ensure!(
        normalize_url(&PackageUrl::Root) == "ROOT",
        "the root package normalizes to a fixed token",
    );

    Ok(())
}

#[cfg(test)]
#[test]
fn test_resolve_submodule_url_forms() -> anyhow::Result<()> {
    let work: PathBuf = Path::new(".gitvenv/parent").to_path_buf();

    let absolute: PackageUrl =
        PackageUrl::GitUrl("https://gitlab.com/upstream/parent.git".to_string());
    let sub = |raw: &str, parent: &PackageUrl| -> String {
        resolve_submodule_url(raw.to_string(), parent, &work)
    };

    anyhow::ensure!(
        sub("https://elsewhere.git", &absolute) == "https://elsewhere.git",
        "a url carrying a scheme is used as written: {}",
        sub("https://elsewhere.git", &absolute),
    );
    anyhow::ensure!(
        sub("git@github.com:org/dep.git", &absolute) == "git@github.com:org/dep.git",
        "the scp-like form counts as absolute: {}",
        sub("git@github.com:org/dep.git", &absolute),
    );

    // git resolves a scheme-less submodule url against the *parent's remote*,
    // dropping only the last path segment -- not against the checkout directory.
    anyhow::ensure!(
        sub("dep.git", &absolute) == "https://gitlab.com/upstream/dep.git",
        "a relative url must be resolved against the parent remote: {}",
        sub("dep.git", &absolute),
    );
    anyhow::ensure!(
        sub("nested/dep.git", &absolute) == "https://gitlab.com/upstream/nested/dep.git",
        "only the last segment of the parent url is dropped: {}",
        sub("nested/dep.git", &absolute),
    );

    // A local parent written as a bare path (no scheme) has no remote to lean on, so
    // the checkout directory is the base.
    let local: PackageUrl = PackageUrl::GitUrl("/home/gipm/fixtures/parent.git".to_string());
    anyhow::ensure!(
        sub("dep.git", &local) == ".gitvenv/parent/dep.git",
        "a scheme-less local parent has no remote to resolve against: {}",
        sub("dep.git", &local),
    );

    // A `file://` parent does carry "://", so it takes the remote-resolution branch: the
    // fixture manifests in this repository use exactly that spelling, which is why the
    // submodule url resolves against the fixture directory rather than the checkout.
    let filed: PackageUrl = PackageUrl::GitUrl("file:///home/gipm/fixtures/parent.git".to_string());
    anyhow::ensure!(
        sub("dep.git", &filed) == "file:///home/gipm/fixtures/dep.git",
        "a file:// parent is treated as a remote, not as a checkout directory: {}",
        sub("dep.git", &filed),
    );

    let parentless: PackageUrl = PackageUrl::GitUrl("parent".to_string());
    anyhow::ensure!(
        sub("dep.git", &parentless) == ".gitvenv/parent/dep.git",
        "a parent url with no path separator leaves no base to use: {}",
        sub("dep.git", &parentless),
    );

    Ok(())
}

#[cfg(test)]
#[test]
fn test_extract_version_from_tag() -> anyhow::Result<()> {
    let underscores: Option<Vec<[String; 2]>> = Some(vec![["_".to_string(), ".".to_string()]]);
    let nothing: Option<Vec<[String; 2]>> = None;

    let shown = |v: &Option<Version>| -> String {
        match v {
            Some(v) => format!("{}", v),
            None => "<rejected>".to_string(),
        }
    };

    let tagged: Option<Version> =
        GitPackage::extract_version_from_tag("curl-1_0_0", Some("curl-"), &underscores);
    anyhow::ensure!(
        shown(&tagged) == "1.0.0",
        "a prefixed, underscored tag must become a version: {}",
        shown(&tagged),
    );

    let unprefixed: Option<Version> =
        GitPackage::extract_version_from_tag("v1.2.3", None, &nothing);
    anyhow::ensure!(
        shown(&unprefixed) == "1.2.3",
        "a bare v-prefix is stripped without any prefix configured: {}",
        shown(&unprefixed),
    );

    let wrong_case: Option<Version> =
        GitPackage::extract_version_from_tag("v0.9.1", Some("V"), &nothing);
    anyhow::ensure!(
        shown(&wrong_case) == "0.9.1",
        "the prefix match is case-insensitive: {}",
        shown(&wrong_case),
    );

    let wrong_prefix: Option<Version> =
        GitPackage::extract_version_from_tag("0.9.1", Some("v"), &nothing);
    anyhow::ensure!(
        wrong_prefix.is_none(),
        "a tag that does not carry the configured prefix is not a version: {}",
        shown(&wrong_prefix),
    );

    let unrewritten: Option<Version> =
        GitPackage::extract_version_from_tag("curl-1_2_0", Some("curl-"), &nothing);
    anyhow::ensure!(
        unrewritten.is_none(),
        "without a replacement the underscores stay and the tag is not a version: {}",
        shown(&unrewritten),
    );

    let prerelease: Option<Version> =
        GitPackage::extract_version_from_tag("1.2.3-rc1", None, &nothing);
    anyhow::ensure!(
        prerelease.is_none(),
        "a pre-release tag must not be offered as a version: {}",
        shown(&prerelease),
    );
    let built: Option<Version> = GitPackage::extract_version_from_tag("1.2.3+opt", None, &nothing);
    anyhow::ensure!(
        built.is_none(),
        "a build-suffixed tag must not be offered as a version: {}",
        shown(&built),
    );
    let not_a_version: Option<Version> =
        GitPackage::extract_version_from_tag("release-notes", None, &nothing);
    anyhow::ensure!(
        not_a_version.is_none(),
        "an unrelated tag is not a version: {}",
        shown(&not_a_version),
    );

    let empty_prefix: Option<Version> =
        GitPackage::extract_version_from_tag("1.0.0", Some(""), &nothing);
    anyhow::ensure!(
        shown(&empty_prefix) == "1.0.0",
        "an empty prefix must match every tag: {}",
        shown(&empty_prefix),
    );

    Ok(())
}

#[cfg(test)]
#[test]
fn test_package_paths() -> anyhow::Result<()> {
    let alpha: GitPackage = GitPackage::new(
        PackageUrl::GitUrl("https://github.com/upstream/alpha.git".to_string()),
        None,
        None,
    );
    let spelled_other: GitPackage = GitPackage::new(
        PackageUrl::GitUrl("git@github.com:upstream/alpha.git".to_string()),
        None,
        None,
    );
    let beta: GitPackage = GitPackage::new(
        PackageUrl::GitUrl("https://github.com/upstream/beta.git".to_string()),
        None,
        None,
    );
    let slashed: GitPackage = GitPackage::new(
        PackageUrl::GitUrl("https://github.com/upstream/alpha.git/".to_string()),
        None,
        None,
    );
    let backslashed: GitPackage = GitPackage::new(
        PackageUrl::GitUrl("https://github.com\\upstream\\alpha.git".to_string()),
        None,
        None,
    );

    anyhow::ensure!(
        alpha.name() == "alpha",
        "name() must take the last segment of the *normalized* url: {}",
        alpha.name(),
    );
    anyhow::ensure!(
        spelled_other.name() == alpha.name(),
        "two spellings of one repo must share one name: {} vs {}",
        spelled_other.name(),
        alpha.name(),
    );
    anyhow::ensure!(
        beta.name() == "beta",
        "distinct repos must get distinct names: {}",
        beta.name(),
    );

    let checkout: PathBuf = alpha.get_checkout_path().unwrap();
    anyhow::ensure!(
        checkout.ends_with("alpha"),
        "the checkout directory is named after the repository, .git suffix gone: {}",
        checkout.display(),
    );
    anyhow::ensure!(
        slashed.get_checkout_path().unwrap() == checkout,
        "a trailing slash must not fork the checkout directory: {}",
        slashed.get_checkout_path().unwrap().display(),
    );
    anyhow::ensure!(
        backslashed.get_checkout_path().unwrap() == checkout,
        "a backslash-separated url must land in the same checkout: {}",
        backslashed.get_checkout_path().unwrap().display(),
    );
    anyhow::ensure!(
        beta.get_checkout_path().unwrap() != checkout,
        "distinct repos must not share a checkout directory",
    );

    let home: PathBuf = home_dir().expect("Could not determine home directory");
    let db_root: PathBuf = home.join(".gipm").join("db");

    let alpha_db: PathBuf = alpha.get_database_path().unwrap();
    anyhow::ensure!(
        alpha_db.starts_with(&db_root),
        "the database cache must live under {}: {}",
        db_root.display(),
        alpha_db.display(),
    );
    anyhow::ensure!(
        alpha_db == spelled_other.get_database_path().unwrap(),
        "one repository must occupy one cache entry, whatever the spelling: {} vs {}",
        alpha_db.display(),
        spelled_other.get_database_path().unwrap().display(),
    );
    anyhow::ensure!(
        alpha_db != beta.get_database_path().unwrap(),
        "distinct repositories must not collide in the cache: {}",
        alpha_db.display(),
    );

    // A package that was never fetched has no database, and the membership probes
    // must answer "no" rather than failing -- that is what lets sync decide to refetch.
    anyhow::ensure!(
        alpha.does_ref_exist_in_db("1.0.0").unwrap_or(false) == false,
        "a missing database must answer 'no ref', not an error",
    );
    let sha = gix::ObjectId::from_hex("aa5a6e02b60c7b6077f6c5d90a10fff0badbe7c5".as_bytes());
    anyhow::ensure!(
        sha.is_ok() && alpha.does_id_exist_in_db(sha.unwrap()).unwrap_or(false) == false,
        "a missing database must answer 'no object', not an error",
    );

    Ok(())
}

#[cfg(test)]
#[test]
fn test_database_usability() -> anyhow::Result<()> {
    use std::fs::write;

    let scratch: PathBuf = Path::new("target/gipm-unit-scratch/usability").to_path_buf();
    remove_dir_all(&scratch).unwrap_or_default();

    // A plain directory is not a repository at all.
    let plain: PathBuf = scratch.join("plain");
    create_dir_all(&plain)?;
    anyhow::ensure!(
        !database_is_usable(&plain),
        "a plain directory must not count as a usable database: {}",
        plain.display(),
    );

    // The residue an interrupted fetch leaves behind: it opens as a repository, it
    // even advertises refs, but the objects those refs point at never arrived.
    let residue: PathBuf = scratch.join("residue");
    create_dir_all(&residue.join("objects"))?;
    create_dir_all(&residue.join("refs"))?;
    write(&residue.join("HEAD"), "ref: refs/heads/main\n")?;
    write(
        &residue.join("packed-refs"),
        "# pack-refs with: peeled fully-peeled sorted \naa5a6e02b60c7b6077f6c5d90a10fff0badbe7c5 refs/tags/1.0.0\n",
    )?;

    anyhow::ensure!(
        gix::open(&residue).is_ok(),
        "the residue must still open as a repository, otherwise the assertion below proves nothing",
    );
    anyhow::ensure!(
        !database_is_usable(&residue),
        "an interrupted fetch must not leave a database that later runs trust: {}",
        residue.display(),
    );

    remove_dir_all(&scratch).unwrap_or_default();
    Ok(())
}
