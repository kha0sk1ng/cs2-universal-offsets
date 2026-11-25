//! `cs2-sdk diff <old> <new>`: what changed between two dump directories.
//!
//! Offline only (no process attach). Compares the published JSON files of the
//! `include/` layout: patterns, game events, vtables and offsets.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::{Value, json};

#[derive(Debug, clap::Args)]
pub struct DiffArgs {
    /// Older dump directory (an `include/` tree).
    pub old: PathBuf,
    /// Newer dump directory (an `include/` tree).
    pub new: PathBuf,
    /// Print one JSON object instead of text.
    #[arg(long)]
    pub json: bool,
    /// Exit with code 1 when anything was added, removed or changed.
    #[arg(long)]
    pub fail_on_change: bool,
}

/// One compared section. `moved` is informational only (a pattern whose RVA
/// shifted but whose prologue bytes are the same) and never counts as a change.
#[derive(Debug, Default, Serialize)]
struct Section {
    added: Vec<String>,
    removed: Vec<String>,
    changed: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    moved: Vec<String>,
}

impl Section {
    fn differs(&self) -> bool {
        !(self.added.is_empty() && self.removed.is_empty() && self.changed.is_empty())
    }
}

fn load(dir: &Path, rel: &str) -> Option<Value> {
    let text = std::fs::read_to_string(dir.join(rel)).ok()?;
    serde_json::from_str(text.trim_start_matches('\u{feff}')).ok()
}

fn build_of(dir: &Path) -> Option<u64> {
    load(dir, "manifest.json")?.get("build_number")?.as_u64()
}

fn s(v: &Value, key: &str) -> Option<String> {
    v.get(key).and_then(Value::as_str).map(str::to_owned)
}

/// Generic keyed comparison. `view` maps an entry to a comparable string plus
/// an optional secondary string (compared only for the `moved` list).
fn compare<K: Ord + Clone + ToString>(
    old: &BTreeMap<K, (String, String)>,
    new: &BTreeMap<K, (String, String)>,
) -> Section {
    let mut sec = Section::default();
    for (k, (main_new, aux_new)) in new {
        match old.get(k) {
            None => sec.added.push(k.to_string()),
            Some((main_old, aux_old)) => {
                if main_old != main_new {
                    sec.changed.push(format!("{}: {} -> {}", k.to_string(), main_old, main_new));
                } else if aux_old != aux_new {
                    sec.moved.push(format!("{}: {} -> {}", k.to_string(), aux_old, aux_new));
                }
            }
        }
    }
    for k in old.keys() {
        if !new.contains_key(k) {
            sec.removed.push(k.to_string());
        }
    }
    sec
}

/// name -> (prologue bytes, rva)
fn patterns(dir: &Path) -> Option<BTreeMap<String, (String, String)>> {
    let v = load(dir, "patterns/patterns.json")?;
    let mut map = BTreeMap::new();
    for p in v.get("patterns")?.as_array()? {
        let Some(name) = s(p, "name") else { continue };
        let bytes = s(p, "bytes").unwrap_or_default();
        let rva = s(p, "rva").unwrap_or_default();
        map.insert(name, (bytes, rva));
    }
    Some(map)
}

/// event name -> (id + fields, "")
fn events(dir: &Path) -> Option<BTreeMap<String, (String, String)>> {
    let v = load(dir, "gameevents/gameevents.json")?;
    let mut map = BTreeMap::new();
    for e in v.get("events")?.as_array()? {
        let Some(name) = s(e, "name") else { continue };
        let fields: Vec<String> = e
            .get("fields")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .map(|f| format!("{} {}", s(f, "type").unwrap_or_default(), s(f, "name").unwrap_or_default()))
                    .collect()
            })
            .unwrap_or_default();
        map.insert(name, (format!("({})", fields.join(", ")), String::new()));
    }
    Some(map)
}

/// "module/interface" -> (method count + RTTI class, "")
fn vtables(dir: &Path) -> Option<BTreeMap<String, (String, String)>> {
    let v = load(dir, "interfaces/vtables.json")?;
    let mut map = BTreeMap::new();
    for (module, ifaces) in v.get("modules")?.as_object()? {
        for (iface, info) in ifaces.as_object()? {
            let methods = info.get("methods").and_then(Value::as_array).map_or(0, Vec::len);
            let rtti = s(info, "rtti_class").unwrap_or_default();
            map.insert(format!("{module}/{iface}"), (format!("{methods} methods, {rtti}"), String::new()));
        }
    }
    Some(map)
}

/// "module/name" -> (value, "")
fn offsets(dir: &Path) -> Option<BTreeMap<String, (String, String)>> {
    let v = load(dir, "offsets/offsets.json")?;
    let mut map = BTreeMap::new();
    for (module, names) in v.as_object()? {
        for (name, val) in names.as_object()? {
            let text = val.as_str().map_or_else(|| val.to_string(), str::to_owned);
            map.insert(format!("{module}/{name}"), (text, String::new()));
        }
    }
    Some(map)
}

fn print_section(title: &str, sec: &Section) {
    println!("\n== {title}: +{} -{} ~{} (moved {})", sec.added.len(), sec.removed.len(), sec.changed.len(), sec.moved.len());
    for a in &sec.added {
        println!("  + {a}");
    }
    for r in &sec.removed {
        println!("  - {r}");
    }
    for c in &sec.changed {
        println!("  ~ {c}");
    }
}

pub fn run(args: &DiffArgs) -> Result<i32> {
    for d in [&args.old, &args.new] {
        anyhow::ensure!(d.is_dir(), "{} is not a directory", d.display());
    }

    type Loader = fn(&Path) -> Option<BTreeMap<String, (String, String)>>;
    let loaders: [(&str, Loader); 4] =
        [("patterns", patterns), ("events", events), ("vtables", vtables), ("offsets", offsets)];

    let mut out = serde_json::Map::new();
    let mut differs = false;
    let mut texts: Vec<(String, Section)> = Vec::new();
    for (name, load_fn) in loaders {
        let old = load_fn(&args.old).with_context(|| format!("{name}: missing or unreadable in {}", args.old.display()))?;
        let new = load_fn(&args.new).with_context(|| format!("{name}: missing or unreadable in {}", args.new.display()))?;
        let sec = compare(&old, &new);
        differs |= sec.differs();
        out.insert(name.to_string(), serde_json::to_value(&sec)?);
        texts.push((name.to_string(), sec));
    }

    let (old_b, new_b) = (build_of(&args.old), build_of(&args.new));
    if args.json {
        out.insert("old_build".into(), json!(old_b));
        out.insert("new_build".into(), json!(new_b));
        out.insert("changed".into(), json!(differs));
        println!("{}", Value::Object(out));
    } else {
        let show = |b: Option<u64>| b.map_or("unknown".to_string(), |n| n.to_string());
        println!("build {} -> {}", show(old_b), show(new_b));
        for (title, sec) in &texts {
            print_section(title, sec);
        }
        println!("\n{}", if differs { "changed" } else { "no changes" });
    }
    Ok(i32::from(differs && args.fail_on_change))
}
