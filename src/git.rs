use crate::dependency::{DependencySpecification, parse_dependencies_yaml_content};
use crate::git;
use crate::{PROGRESS, VERBOSE};
use anyhow::{Context, Result};
use gix::ObjectId;
use gix::progress::prodash::Progress;
use gix::progress::prodash::tree::Item;
use gix::refs::PartialNameRef;
use gix::worktree::state::checkout::Options;
use gix::{self};
use regex::Regex;
use semver::{Version, VersionReq};
use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet};
use std::env::{current_dir, home_dir};
use std::fmt;
use std::fs::{create_dir_all, metadata, remove_dir_all, remove_file, set_permissions};
use std::hash::{Hash, Hasher};
use std::path::PathBuf;
use std::process::Command;
use std::time::Instant;

#[derive(Debug, Clone, Eq)]
pub struct GitPackage {
    pub url: String,
    pub prefix: Option<String>,
    pub replacements: Option<Vec<[String; 2]>>,
    db_up_to_date: bool,
    // Map of versions to tag names
    all_versions: Option<HashMap<Version, String>>,
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
        url: String,
        prefix: Option<String>,
        replacements: Option<Vec<[String; 2]>>,
    ) -> Self {
        GitPackage {
            url,
            prefix,
            replacements,
            db_up_to_date: false,
            all_versions: None,
        }
    }

    pub fn get_database_path(&self) -> anyhow::Result<PathBuf> {
        get_database_path(&self.url)
    }

    pub fn get_available_versions(&self) -> Option<&HashMap<Version, String>> {
        self.all_versions.as_ref()
    }

    pub fn update_db(&mut self) -> anyhow::Result<()> {
        if !self.db_up_to_date {
            self.clone_dependency_database()?;
            self.db_up_to_date = true;
        }
        if self.all_versions.is_none() {
            self.update_available_versions()?;
        }
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
        let db_path = git::get_database_path(&self.url)?;

        if !db_path.exists() {
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
        let target = tag_ref.peel_to_id_in_place()?;
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
        match &self.all_versions {
            None => None,
            Some(map) => map.get(version).cloned(),
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
        if !db_path.exists() {
            return Ok(false);
        }

        let object = object.into();

        let object_str = match &object {
            ObjectId::Sha1(id) => std::str::from_utf8(id)?,
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
        if !db_path.exists() {
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
        // Extract the repository name from the end of the URL and create a PathBuf: cwd/.gitvenv/<repo>

        // Remove trailing '/' if present
        let url = self.url.trim_end_matches('/');
        // Get the last path segment after '/' or '\'
        let repo_url = self.url.rsplit(&['/', '\\'][..]).next().unwrap_or(url);
        // Remove .git suffix if present
        let repo_name = repo_url
            .strip_suffix(".git")
            .unwrap_or(repo_url)
            .to_string();

        let cwd = current_dir()?;
        Ok(cwd.join(".gitvenv").join(repo_name))
    }

    /// Get all available versions from a git package
    pub fn update_available_versions(&mut self) -> Result<&HashMap<Version, String>> {
        let db_path = self.get_database_path()?;

        if !db_path.exists() {
            anyhow::bail!("Database for dependency {} does not exist", self.name());
        }

        self.all_versions = Some(HashMap::new());

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
                if *VERBOSE {
                    println!("Extracted version {version} from tag {tag}");
                }
                match &mut self.all_versions {
                    None => {
                        anyhow::bail!(
                            "all_versions not initialized, must have been by this function"
                        );
                    }
                    Some(map) => {
                        map.insert(version, tag.to_string());
                    }
                }
            } else if *VERBOSE {
                println!("Failed to extract version from tag: {tag}");
            }
        }

        Ok(self
            .all_versions
            .as_ref()
            .expect("all_versions not initialized, must have been by this function"))
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
        Version::parse(&tag).ok()
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
        if *VERBOSE {
            println!("Database path for {}: {:?}", self.name(), path);
        }

        if let Ok(repo) = gix::open(&path) {
            if *VERBOSE {
                println!("Found existing database at {path:?}");
            }
            // Open existing repository and fetch updates
            let remote = repo
                .find_fetch_remote(Some("origin".into()))
                .expect("Failed to find fetch remote")
                .with_fetch_tags(gix::remote::fetch::Tags::All);

            let progress = &PROGRESS;

            let start = Instant::now();

            let update_progress_overall =
                progress.add_child(format!("Fetching {} in {}", self.name(), path.display()));

            let mut sub_progress_fetch = progress.add_child("");

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
            // First make the directory
            create_dir_all(&path).expect("Failed to create database clone directory");
            let url = gix::url::parse(self.url.as_str().into()).expect("Failed to parse URL");

            let progress = &PROGRESS;

            let start = Instant::now();

            let mut clone_progress_overall = progress.add_child(format!(
                "Cloning dependency database for {} in {}",
                self.name(),
                path.display()
            ));

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
                &"remote.origin.url",
                bare_db_path.to_str().unwrap().as_bytes(),
            )
            .expect("Failed to set remote URL");
        config.commit().expect("Failed to commit config");

        // Check if the repository is dirty (has uncommitted changes)
        // We'll use a simple approach to check for uncommitted changes
        let dirty = checkout_repo.is_dirty()?;
        if dirty {
            println!(
                "Warning: Repository at {checkout_dir:?} has uncommitted changes, proceeding anyway",
            );
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
                &"remote.origin.url",
                bare_db_path.to_str().unwrap().as_bytes(),
            )
            .expect("Failed to set remote URL");
        config.commit().expect("Failed to commit config");

        // Check if the repository is dirty (has uncommitted changes)
        // We'll use a simple approach to check for uncommitted changes
        let dirty = checkout_repo.is_dirty()?;
        if dirty {
            println!(
                "Warning: Repository at {checkout_dir:?} has uncommitted changes, proceeding anyway",
            );
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
        // Check if the repository already exists, which it shouldn't if we're cloning
        let checkout_dir = self.get_checkout_path()?;
        let bare_db_path = self.get_database_path()?;
        let object: ObjectId = object.into();
        if gix::open(&checkout_dir).is_ok() {
            anyhow::bail!(
                "Repository already exists at {} - should call checkout, not clone",
                self.get_checkout_path()?.display()
            )
        }

        if !&checkout_dir.exists() {
            create_dir_all(&checkout_dir).context(format!(
                "Failed to create checkout directory: {checkout_dir:?}"
            ))?;
        }

        // TODO: This could be made more efficient for syncs by only cloning the one ref we need to the database repo
        let db_repo = match gix::open(&bare_db_path) {
            Ok(repo) => repo,
            Err(_) => {
                self.clone_dependency_database().context(format!(
                    "Failed to open database repository at {bare_db_path:?}"
                ))?;
                gix::open(&bare_db_path)?
            }
        };

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
            &checkout_dir,
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

        let (repo, _outcome) = prepare
            .main_worktree(
                &mut sub_progress_checkout_overall,
                &gix::interrupt::IS_INTERRUPTED,
            )
            .context("Failed to checkout")?;

        let checkout_result =
            self.checkout_object_from_database(object, &mut sub_progress_checkout_overall);

        sub_progress_checkout_overall.inc();

        let subs = repo.submodules()?;
        if let Some(submodules) = subs {
            eprintln!(
                "Warning: submodule support is not yet fully implemented Submodules \
                will be updated using the `git` cli. Detected submodules in {}:",
                self.name()
            );
            for s in submodules {
                eprintln!("  - {}", s.name());
            }

            update_submodules(
                checkout_dir.to_str().expect("path should resolve a str"),
                Some(&mut sub_progress_checkout_overall),
            )
            .context("submodule update failed")?;
        };

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
        f.set_existing_raw_value(&"remote.origin.url", self.url.as_bytes())
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
        let checkout_repo = gix::open(self.get_checkout_path()?)?;
        let object = object.into();
        let commit = match checkout_repo.find_object(object) {
            Ok(object) => object.peel_to_commit()?,
            Err(e) => match e {
                gix::object::find::existing::Error::NotFound { oid: _ } => {
                    // Fetch the object first
                    self.fetch_ref_from_db(object, sub_progress)?;
                    checkout_repo.find_object(object)?.peel_to_commit()?
                }
                _ => {
                    anyhow::bail!(
                        "Failed to find object {object} in repository {}: {e}",
                        self.name()
                    );
                }
            },
        };

        let mut sub_progress_checkout =
            sub_progress.add_child(format!("Checking out {} id {}", self.name(), object));

        if let Ok(Some(t)) = checkout_repo.try_find_object(object)
            && let Ok(head) = checkout_repo.head()
            && let Ok(head_id) = head.into_peeled_id()
            && t.id == head_id
        {
            let subs = checkout_repo.submodules()?;
            if let Some(submodules) = subs {
                eprintln!(
                    "Warning: submodule support is not yet fully implemented Submodules \
                will be updated using the `git` cli. Detected submodules in {}:",
                    self.name()
                );
                for s in submodules {
                    eprintln!("  - {}", s.name());
                }

                sub_progress_checkout.info("updating submodules".to_string());

                update_submodules(
                    checkout_repo
                        .workdir()
                        .expect("should have a workdir")
                        .to_str()
                        .expect("path should resolve a str"),
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

        // Set checkout options to handle untracked files properly
        let opts = Options {
            destination_is_initially_empty: false, // We're updating existing worktree
            overwrite_existing: false,             // Force overwrite existing files
            ..Default::default()
        };

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
                        if *VERBOSE {
                            println!("Removed file: {file_path}");
                        }
                    } else if full_path.is_dir() {
                        remove_dir_all(&full_path)?;
                        remove_items.inc();
                        if *VERBOSE {
                            println!("Removed directory: {file_path}");
                        }
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

                            // Log what changed
                            if *VERBOSE {
                                let current_str = format!("{normalized_current:o}");
                                let expected_str = format!("{normalized_expected:o}");
                                println!(
                                    "Updated permissions for {file_path}: {current_str} -> {expected_str}"
                                );
                            }
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
                            permissions.set_readonly(false);
                            set_permissions(&full_path, permissions)?;
                            if *VERBOSE {
                                println!(
                                    "Updated permissions for {file_path}: readonly -> writable (executable)"
                                );
                            }
                            fix_permissions.inc();
                        } else if !is_executable && !readonly {
                            permissions.set_readonly(true);
                            set_permissions(&full_path, permissions)?;
                            if *VERBOSE {
                                println!(
                                    "Updated permissions for {file_path}: writable -> readonly (not executable)"
                                );
                            }
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
        if let Some(submodules) = subs {
            eprintln!(
                "Warning: submodule support is not yet fully implemented Submodules \
                will be updated using the `git` cli. Detected submodules in {}:",
                self.name()
            );
            for s in submodules {
                eprintln!("  - {}", s.name());
            }

            update_submodules(
                checkout_repo
                    .workdir()
                    .expect("should have a workdir")
                    .to_str()
                    .expect("path should resolve a str"),
                Some(sub_progress),
            )
            .context("submodule update failed")?;
        };

        Ok(())
    }

    pub fn checkout_from_database(&self, version: &Version) -> anyhow::Result<()> {
        // Path to the bare database repository
        let bare_db_path = self.get_database_path()?;
        if !bare_db_path.exists() {
            anyhow::bail!("Database for does not exist at {:?}", bare_db_path);
        }

        let progress = &PROGRESS;

        let start_overall = Instant::now();

        let tag_name = self.get_tag_name(version).ok_or(anyhow::anyhow!(
            "Version {version} not found in all_versions"
        ))?;

        // Handle existing checkout directory
        let checkout_dir = self.get_checkout_path()?;

        let mut sub_progress_checkout_overall = progress.add_child(format!(
            "Cloning {} ref {tag_name} in {checkout_dir:?}",
            self.name(),
        ));

        if checkout_dir.exists() {
            // Check if it's a git repository
            match gix::open(&checkout_dir) {
                Ok(checkout_repo) => {
                    if *VERBOSE {
                        println!("Found existing git repository at {checkout_dir:?}");
                    }

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

            // Furthermore, calling the chekout_object_from_database will handle submodule init.

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
        f.set_existing_raw_value(&"remote.origin.url", self.url.as_bytes())
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

pub fn normalize_url(url: &str) -> String {
    // Try to parse as a URL to handle userinfo (username:token@)
    // If parsing fails, fallback to manual normalization
    if let Ok(parsed) = url::Url::parse(url) {
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
        // Add path, removing trailing .git and slashes
        let mut path = parsed.path().trim_end_matches('/').to_string();
        if let Some(stripped) = path.strip_suffix(".git") {
            path = stripped.to_string();
        }
        normalized.push_str(&path);
        // Lowercase for case-insensitivity
        return normalized.to_ascii_lowercase();
    }

    // Fallback: manual normalization for scp-like and other forms
    let url = url
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_start_matches("ssh://")
        .trim_start_matches("git://")
        .trim_start_matches("git@");

    // Remove userinfo if present (username:token@)
    let url = if let Some(at_idx) = url.find('@') {
        &url[at_idx + 1..]
    } else {
        url
    };

    // For git@github.com:user/repo.git, convert ':' to '/'
    let url = if let Some(idx) = url.find(':') {
        // Only replace the first ':' after the host
        let (host, rest) = url.split_at(idx);
        let rest = &rest[1..]; // skip the ':'
        format!("{host}/{rest}")
    } else {
        url.to_string()
    };

    // Remove trailing .git if present
    let url = url.strip_suffix(".git").unwrap_or(&url);

    // Remove trailing slashes
    let url = url.trim_end_matches('/');

    // Lowercase for case-insensitivity
    url.to_ascii_lowercase()
}

pub fn get_database_path(
    // path should be a hashed version of the url
    url: &str,
) -> anyhow::Result<PathBuf> {
    // Normalize the URL so that different schemes and forms hash the same way

    let normalized = normalize_url(url);

    // Hash the normalized url
    let mut hasher = DefaultHasher::new();
    normalized.hash(&mut hasher);
    let hash = format!("{:x}", hasher.finish());

    let home = home_dir().expect("Could not determine home directory");
    let path: PathBuf = home.join(".gipm").join("db").join(hash);
    Ok(path)
}

fn update_submodules(git_dir: &str, progress: Option<&mut Item>) -> anyhow::Result<()> {
    let subprogress = progress.map(|item| item.add_child("submodule update"));
    let output = Command::new("git")
        .arg("submodule")
        .arg("update")
        .arg("--init")
        .arg("--recursive")
        .args(["--depth", "1"])
        .args([
            "--jobs",
            &std::thread::available_parallelism()
                .unwrap()
                .get()
                .to_string(),
        ])
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .current_dir(git_dir)
        .output()
        .context("Failed to run git submodule update")?;

    if output.status.success() {
        if let Some(subprogress) = subprogress {
            subprogress.done(format!(
                "Submodules updated successfully:\n{}",
                String::from_utf8_lossy(&output.stdout)
            ));
        }
        Ok(())
    } else {
        if let Some(subprogress) = subprogress {
            subprogress.fail(format!(
                "Failed to update submodules: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        anyhow::bail!(
            "Failed to update submodules: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
