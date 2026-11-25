// cs2-universal-dumper
// --------------------
// Two passes, one binary: offsets dump + PE/section-aware Pattern scan.
//
// Output layout (flat root, single `schemas/` subdir for per-module headers):
//
//     <OutputRoot>/
//         cs2.hpp                    single-include amalgamation
//         macros.hpp                 SCHEMA_FIELD macro family
//         interfaces.hpp             typed interface accessors
//         entity_system.hpp          CGameEntitySystem helpers
//         buttons.{hpp,json}         symbolic button table
//         offsets.{hpp,json}         RIPREL patterns + dwXxx aliases
//         vtables.{hpp,json}         interface vtable layouts
//         netvars.{hpp,json}         split networked-field offsets (optional)
//         protobufs.{hpp,json}       libprotobuf message layouts
//         patterns.{hpp,json}      resolved Pattern catalogue
//         ida_tutorials.json         curated IDA walkthroughs per Pattern
//         verified_features.{hpp,json}  hand-curated working catalogue
//         manifest.json              run metadata
//         cs2-sdk.log                warn+ log
//         schemas/<module>_dll.hpp   typed schema classes per module

use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::str::FromStr;


use anyhow::{Context, Result};
use chrono::Local;
use clap::{ArgAction, Parser, Subcommand};
use log::LevelFilter;
use memflow::prelude::v1::*;
use serde_json::json;
use simplelog::*;


mod analysis;
mod checks;
mod diff;
mod events_gen;
mod memory;
mod output;
mod patterns;
mod source2;
mod ui;

#[derive(Debug, Parser)]
#[command(
    author,
    version,
    about = "CS2 Universal Dumper — offsets + patterns in one run",
    args_conflicts_with_subcommands = true
)]
struct Args {
    #[command(subcommand)]
    cmd: Option<Cmd>,

    #[arg(short, long)]
    connector: Option<String>,

    #[arg(short = 'a', long)]
    connector_args: Option<String>,

    #[arg(short, long, default_value_t = 4)]
    indent_size: usize,

    /// Output directory — the SDK is laid out as an `include/` tree
    /// so the repo can be consumed as a git submodule.
    #[arg(short, long, default_value = "include")]
    output: PathBuf,

    #[arg(short, long, default_value = "cs2.exe")]
    process_name: String,

    #[arg(short, long, action = ArgAction::Count)]
    verbose: u8,

    #[arg(long)]
    skip_offsets: bool,

    #[arg(long)]
    skip_patterns: bool,

    #[arg(long)]
    no_sound: bool,

    /// Previous dump directory. Its patterns/patterns.json lets the scanner
    /// re-anchor patterns that stopped matching after a CS2 update, as long
    /// as the function itself did not change (see status.json auto_healed).
    #[arg(long, default_value = "include")]
    previous: PathBuf,

    /// No banner, colors, progress or sound; only errors go to stderr.
    #[arg(long)]
    quiet: bool,

    /// Print one JSON summary object on stdout (implies --quiet). Also used
    /// for failures: `{"ok":false,"error":"..."}`.
    #[arg(long)]
    json: bool,

    /// Probe only patterns whose name contains one of these (comma separated,
    /// case-insensitive). Read-only: writes no files and skips the offsets pass.
    #[arg(long, value_delimiter = ',', value_name = "NAME")]
    only: Vec<String>,

    /// Shell command to run after a successful dump. `{out}` is replaced with
    /// the absolute output directory and `{build}` with the build number.
    /// Wrap placeholders in quotes if the path may contain spaces. A failing
    /// hook makes the exit code 2.
    #[arg(long, value_name = "COMMAND")]
    post_dump: Option<String>,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Compare two dump directories (patterns, game events, vtables, offsets).
    Diff(diff::DiffArgs),
    /// Generate a typed C++ header for every game event from gameevents.json.
    Events(events_gen::EventsArgs),
}

fn main() {
    let args = Args::parse();
    let json_mode = args.json || matches!(&args.cmd, Some(Cmd::Diff(d)) if d.json);
    let code = match run(args) {
        Ok(code) => code,
        Err(e) => {
            if json_mode {
                println!("{}", json!({ "ok": false, "error": format!("{e:#}") }));
            } else {
                eprintln!("Error: {e:?}");
            }
            1
        }
    };
    std::process::exit(code);
}

fn run(args: Args) -> Result<i32> {
    match &args.cmd {
        Some(Cmd::Diff(a)) => return diff::run(a),
        Some(Cmd::Events(a)) => return events_gen::run(a),
        None => {}
    }

    ui::init(args.no_sound, args.quiet || args.json);
    ui::banner();
    ui::sound(ui::Cue::Start);

    if !args.only.is_empty() {
        return run_only(&args);
    }

    let now = Local::now();
    let out_dir = args.output.clone();
    let schemas_dir  = out_dir.join("schemas");
    let sig_dir      = out_dir.join("patterns"); // lowercase: the site + git track include/patterns/
    let off_dir      = out_dir.join("offsets");
    let proto_dir    = out_dir.join("protobufs");
    let ifc_dir      = out_dir.join("interfaces");
    for d in [&out_dir, &schemas_dir, &sig_dir, &off_dir, &proto_dir, &ifc_dir] {
        fs::create_dir_all(d)
            .with_context(|| format!("failed to create {}", d.display()))?;
    }

    init_logging(Some(&out_dir), args.verbose, args.quiet || args.json)?;

    ui::section("Session");
    ui::kv("Timestamp", &now.format("%Y-%m-%d %H:%M:%S").to_string());
    ui::kv("Output", &out_dir.display().to_string());
    ui::kv("Process", &args.process_name);

    ui::kv("Offsets", if args.skip_offsets { "skipped" } else { "enabled" });
    ui::kv("Patterns", if args.skip_patterns { "skipped" } else { "enabled" });

    ui::section("Attach");
    let mut os = build_os(&args)?;
    let mut process = os
        .process_by_name(&args.process_name)
        .with_context(|| format!("process '{}' not found", args.process_name))?;
    let pid = process.info().pid;
    ui::ok(&format!("attached to {} (pid {})", args.process_name, pid));

    // --- stage 1: offsets --------------------------------------------------
    let mut offsets_ok = true;
    let mut build_number: Option<u32> = None;
    let mut analysis_result: Option<analysis::AnalysisResult> = None;

    if !args.skip_offsets {
        ui::section("Offsets, interfaces, buttons, schemas");
        ui::sound(ui::Cue::Step);
        match analysis::analyze_all(&mut process) {
            Ok(result) => {
                ui::ok(&format!(
                    "interfaces: {} across {} modules",
                    result.interfaces.iter().map(|(_, v)| v.len()).sum::<usize>(),
                    result.interfaces.len()
                ));
                ui::ok(&format!(
                    "offsets: {} across {} modules",
                    result.offsets.iter().map(|(_, v)| v.len()).sum::<usize>(),
                    result.offsets.len()
                ));
                let (cc, ec) = result.schemas.values().fold((0, 0), |(c, e), (cv, ev)| {
                    (c + cv.len(), e + ev.len())
                });
                ui::ok(&format!(
                    "schemas: {} classes, {} enums across {} modules",
                    cc, ec, result.schemas.len()
                ));

                build_number = result
                    .offsets
                    .iter()
                    .find_map(|(mname, offs)| {
                        let m = process.module_by_name(mname).ok()?;
                        let o = offs.iter().find(|(n, _)| *n == "dwBuildNumber")?.1;
                        process.read::<u32>(m.base + o).data_part().ok()
                    });

                if let Err(e) = output::dump_sdk_extras(&out_dir, &result, build_number) {
                    ui::warn(&format!("sdk extras emitter failed: {}", e));
                } else {
                    ui::ok("sdk extras emitted");
                }

                let total_vts: usize = result.vtables.values().map(|m| m.len()).sum();
                let total_methods: usize = result
                    .vtables
                    .values()
                    .flat_map(|m| m.values())
                    .map(|i| i.methods.len())
                    .sum();
                let total_rtti: usize = result
                    .vtables
                    .values()
                    .flat_map(|m| m.values())
                    .filter(|i| i.rtti_class.is_some())
                    .count();
                if total_vts > 0 {
                    ui::ok(&format!(
                        "vtables: {} interfaces, {} method slots, {} RTTI class names",
                        total_vts, total_methods, total_rtti
                    ));
                }

                analysis_result = Some(result);
            }
            Err(e) => {
                offsets_ok = false;
                ui::err(&format!("offsets pass failed: {}", e));
            }
        }
    }

    // --- stage 2: patterns ----------------------------------------------
    let mut sigs_ok = true;
    let mut sig_report: Option<patterns::PatternReport> = None;

    if !args.skip_patterns {
        ui::section("Patterns (PE/section aware)");
        ui::sound(ui::Cue::Step);

        let prev_file = args.previous.join("patterns").join("patterns.json");
        let previous = patterns::load_previous(&prev_file);
        match &previous {
            Some(p) => ui::kv("Previous dump", &format!("{} ({} entries with prologues)", prev_file.display(), p.len())),
            None => ui::kv("Previous dump", "none (self-healing off)"),
        }
        match patterns::scan_all(&mut process, patterns::database::CS2_PATTERNS, previous.as_ref()) {
            Ok(report) => {
                ui::ok(&format!(
                    "{}/{} patterns resolved across {} module(s)",
                    report.found,
                    report.total,
                    report.modules.len()
                ));

                let healed: Vec<&str> = report.hits.iter().filter(|h| h.healed_from.is_some()).map(|h| h.name.as_str()).collect();
                if !healed.is_empty() {
                    ui::warn(&format!(
                        "{} pattern(s) re-anchored from the previous dump's prologues: {} — run `py tools/verify/heal.py --apply` to put the new patterns in database.rs",
                        healed.len(),
                        healed.join(", ")
                    ));
                }
                fs::write(sig_dir.join("patterns.json"), format_found_patterns(&report))?;
                fs::write(sig_dir.join("patterns.hpp"), patterns::writers::render_hpp(&report.hits))?;
                ui::ok("wrote patterns/patterns.{hpp,json}");

                // Feature recipes: offsets from this run's schema, globals from the
                // offset pass, function RVAs/patterns from this pattern pass.
                let _ = fs::write(
                    out_dir.join("verified_features.json"),
                    output::verified::render_json(
                        build_number,
                        analysis_result.as_ref().map(|r| &r.schemas),
                        analysis_result.as_ref().map(|r| &r.offsets),
                        &report.hits,
                    ),
                );

                // Engine struct layouts: function/instance RVAs from this run.
                match output::write_engine_structs(&out_dir, build_number, &report.hits) {
                    Ok(()) => ui::ok(&format!("engine structs emitted ({})", output::engine_structs::ENGINE_STRUCTS.len())),
                    Err(e) => ui::warn(&format!("engine structs emit failed: {}", e)),
                }

                // RIPREL patterns + a2x-style dwXxx aliases + registered-interface RVAs.
                let empty_offsets = analysis::OffsetMap::new();
                let empty_ifaces = analysis::InterfaceMap::new();
                let offset_map = analysis_result.as_ref().map(|r| &r.offsets).unwrap_or(&empty_offsets);
                let iface_map  = analysis_result.as_ref().map(|r| &r.interfaces).unwrap_or(&empty_ifaces);
                fs::write(off_dir.join("offsets.hpp"), patterns::offsets_writer::render_offsets_hpp(&report.hits, offset_map, iface_map))?;
                fs::write(off_dir.join("offsets.json"), patterns::offsets_writer::render_offsets_json(offset_map))?;
                fs::write(off_dir.join("offsets_all.json"), patterns::offsets_writer::render_offsets_all_json(&report.hits, offset_map, iface_map))?;

                // buttons.{hpp,json}
                if let Some(result) = analysis_result.as_ref()
                    && !result.buttons.is_empty()
                {
                    if let Err(e) = output::write_buttons(&out_dir, &result.buttons) {
                        ui::warn(&format!("buttons emit failed: {}", e));
                    } else {
                        ui::ok(&format!(
                            "buttons emitted ({} entries)",
                            result.buttons.len()
                        ));
                    }
                }


                // ConVars / ConCommands — read-only walk of the tier0 CCvar
                // registry, anchored on the `pCvarRegistry` global. Emits a
                // structured catalogue for the site + a reference header.
                if let Some(hit) = report.hits.iter().find(|h| h.name == "pCvarRegistry" && h.found)
                    && let Some(va) = hit.va
                {
                    match analysis::convars::walk(&mut process, va) {
                        Ok(dump) => {
                            let cv_dir = out_dir.join("convars");
                            if let Err(e) = fs::create_dir_all(&cv_dir) {
                                ui::warn(&format!("convars dir create failed: {}", e));
                            } else {
                                let _ = fs::write(
                                    cv_dir.join("convars.json"),
                                    output::convars::render_json(&dump, build_number),
                                );
                                let _ = fs::write(
                                    cv_dir.join("convars.hpp"),
                                    output::convars::render_hpp(&dump, build_number),
                                );
                                ui::ok(&format!(
                                    "convars emitted ({} convars, {} commands)",
                                    dump.convars.len(),
                                    dump.commands.len()
                                ));
                            }
                        }
                        Err(e) => ui::warn(&format!("convars walk failed: {}", e)),
                    }
                }

                // Weapon VData — walk the entity list for weapon entities and
                // read each one's CCSWeaponBaseVData values. Anchored on the
                // `pEntitySystem` global. Coverage = weapons present in-session.
                if let Some(hit) = report.hits.iter().find(|h| h.name == "pEntitySystem" && h.found)
                    && let Some(va) = hit.va
                {
                    match analysis::weapons::walk(&mut process, va, analysis_result.as_ref().map(|r| &r.schemas)) {
                        Ok(weapons) if !weapons.is_empty() => {
                            let wp_dir = out_dir.join("weapons");
                            if fs::create_dir_all(&wp_dir).is_ok() {
                                let _ = fs::write(
                                    wp_dir.join("weapons.json"),
                                    output::weapons::render_json(&weapons, build_number),
                                );
                                ui::ok(&format!("weapons emitted ({} weapons)", weapons.len()));
                            }
                        }
                        Ok(_) => ui::warn("weapons: no weapon entities found (run the dump in a match for coverage)"),
                        Err(e) => ui::warn(&format!("weapons walk failed: {}", e)),
                    }
                }

                // Game Events — walk the CGameEventManager registry for every
                // registered event's name/id/typed field schema.
                if let Some(hit) = report.hits.iter().find(|h| h.name == "pGameEventManager" && h.found)
                    && let Some(va) = hit.va
                {
                    match analysis::gameevents::walk(&mut process, va) {
                        Ok(events) if !events.is_empty() => {
                            let ge_dir = out_dir.join("gameevents");
                            if fs::create_dir_all(&ge_dir).is_ok() {
                                let _ = fs::write(
                                    ge_dir.join("gameevents.json"),
                                    output::gameevents::render_json(&events, build_number),
                                );
                                ui::ok(&format!("game events emitted ({} events)", events.len()));
                            }
                        }
                        Ok(_) => ui::warn("game events: registry empty"),
                        Err(e) => ui::warn(&format!("game events walk failed: {}", e)),
                    }
                }

                // Live entity snapshot — decode every entity in the world at
                // dump time (reuses the `pEntitySystem` anchor).
                if let Some(hit) = report.hits.iter().find(|h| h.name == "pEntitySystem" && h.found)
                    && let Some(va) = hit.va
                {
                    match analysis::entities::walk(&mut process, va, analysis_result.as_ref().map(|r| &r.schemas)) {
                        Ok(ents) if !ents.is_empty() => {
                            let en_dir = out_dir.join("entities");
                            if fs::create_dir_all(&en_dir).is_ok() {
                                let _ = fs::write(
                                    en_dir.join("entities.json"),
                                    output::entities::render_json(&ents, build_number),
                                );
                                ui::ok(&format!("entity snapshot emitted ({} entities)", ents.len()));
                            }
                        }
                        Ok(_) => ui::warn("entities: none found (run the dump in-game)"),
                        Err(e) => ui::warn(&format!("entity snapshot failed: {}", e)),
                    }
                }

                sig_report = Some(report);
            }
            Err(e) => {
                sigs_ok = false;
                ui::err(&format!("patterns pass failed: {}", e));
            }
        }
    }

    // --- stage 3: combined interfaces.hpp/vtables.json (accessors + class wrappers)
    if let Some(result) = analysis_result.as_mut() {
        if let Some(sig) = sig_report.as_ref() {
            analysis::recover_names(&mut result.vtables, &sig.hits);
        }

        if !result.vtables.is_empty() {
            match output::vtables::render_json(&result.vtables) {
                Ok(j) => {
                    let _ = fs::write(ifc_dir.join("vtables.json"), j);
                    let total_methods: usize = result
                        .vtables
                        .values()
                        .flat_map(|m| m.values())
                        .map(|i| i.methods.len())
                        .sum();
                    let total_named: usize = result
                        .vtables
                        .values()
                        .flat_map(|m| m.values())
                        .flat_map(|i| i.methods.iter())
                        .filter(|m| m.name.is_some())
                        .count();
                    ui::ok(&format!(
                        "wrote interfaces/vtables.json ({} methods, {} names recovered)",
                        total_methods, total_named
                    ));
                }
                Err(e) => ui::warn(&format!("vtables.json emit failed: {}", e)),
            }

            // Registered interfaces — discovered via CreateInterface walk in analysis.
            let mut classes: Vec<output::interface_classes::IfaceClass> = result
                .vtables
                .iter()
                .flat_map(|(module, ifaces)| {
                    ifaces.iter().map(move |(iface, info)| {
                        let methods = info.methods.iter().enumerate()
                            .map(|(idx, m)| output::interface_classes::Method { index: idx, name: m.name.clone() })
                            .collect();
                        output::interface_classes::IfaceClass {
                            module: module.clone(),
                            iface_name: iface.clone(),
                            rtti_class: info.rtti_class.clone(),
                            methods,
                            manual: false,
                        }
                    })
                })
                .collect();

            // Vtable-only classes reached via `p*` patterns — discovered by
            // RTTI-walking the singleton at each resolved pattern address.
            if let Some(sig) = sig_report.as_ref() {
                let discovered = analysis::manual_iface::discover(&mut process, sig);
                classes.extend(discovered);
            }

            let _ = fs::write(
                ifc_dir.join("interfaces.hpp"),
                output::interface_classes::render_hpp(&result.interfaces, &classes, build_number),
            );
            ui::ok(&format!(
                "interfaces emitted ({} classes)",
                classes.len()
            ));
        }
    }

    // --- stage 4: protobuf message layouts (offsets + has-bits from the
    // libprotobuf reflection tables — usercmd / netmessages etc.).
    // Run LAST: this pass `read_raw`s several large modules in full, which
    // degrades memflow's later reads — doing it after the Pattern pass keeps
    // patterns reading a clean process.
    let protobufs = analysis::protobufs(&mut process).unwrap_or_default();
    if !protobufs.is_empty() {
        let hpp = output::protobufs::render_hpp(&protobufs, build_number);
        let json = output::protobufs::render_json(&protobufs);
        let _ = fs::write(proto_dir.join("protobufs.hpp"), hpp);
        let _ = fs::write(proto_dir.join("protobufs.json"), json);
        let total: usize = protobufs.values().map(|m| m.len()).sum();
        ui::ok(&format!(
            "protobufs emitted (protobufs.{{json,hpp}}) — {} messages",
            total
        ));
    }

    // --- self-checks + status.json ----------------------------------------
    ui::section("Self-checks");
    let checks_ok = match checks::run(
        &mut process,
        &out_dir,
        &now.to_rfc3339(),
        build_number,
        sig_report.as_ref(),
        analysis_result.as_ref().map(|r| &r.offsets),
        &protobufs,
    ) {
        Ok(ok) => ok,
        Err(e) => {
            ui::warn(&format!("self-checks could not run: {}", e));
            true
        }
    };

    // --- manifest ----------------------------------------------------------
    // Minimal: timestamp, process, build, success flags, Pattern counts,
    // and just the names of the modules we attached to. Per-module
    // base/image/size/timestamp were removed — consumers that need a
    // build-fingerprint use `build_number` directly.
    let sig_counts = sig_report
        .as_ref()
        .map(|r| json!({ "found": r.found, "total": r.total }))
        .unwrap_or(json!(null));

    let module_names = list_loaded_module_names(&mut process);

    let manifest = json!({
        "generated_at": now.to_rfc3339(),
        "process": args.process_name,
        "build_number": build_number,
        "modules": module_names,
        "offsets_ok": offsets_ok,
        "signatures_ok": sigs_ok,
        "signature_counts": sig_counts,
        "checks_ok": checks_ok,
    });
    fs::write(
        out_dir.join("manifest.json"),
        serde_json::to_string_pretty(&manifest)?,
    )?;

    // --- summary -----------------------------------------------------------
    ui::section("Summary");
    ui::kv("Output dir", &out_dir.display().to_string());
    if !args.skip_offsets {
        ui::kv("Offsets", if offsets_ok { "ok" } else { "FAIL" });
    }
    if !args.skip_patterns {
        match &sig_report {
            Some(r) => ui::kv("Patterns", &format!("{} / {}", r.found, r.total)),
            None => ui::kv("Patterns", "FAIL"),
        }
    }
    if let Some(bn) = build_number {
        ui::kv("Build number", &bn.to_string());
    }

    if !args.skip_patterns {
        ui::kv("Self-checks", if checks_ok { "ok" } else { "FAIL (see status.json)" });
    }

    ui::divider();
    let all_ok = offsets_ok && sigs_ok && checks_ok;
    let build = build_number.map(|b| format!("build {b}")).unwrap_or_else(|| "unknown build".into());
    if all_ok {
        ui::sound(ui::Cue::Success);
        ui::done(true, &format!("Dump complete for {build} — written to {}", out_dir.display()));
    } else {
        ui::sound(ui::Cue::Failure);
        ui::done(false, &format!("Dump for {build} failed a check — see status.json and cs2-sdk.log in {}", out_dir.display()));
    }

    // --- post-dump hook (successful dumps only) -----------------------------
    let mut hook_json = serde_json::Value::Null;
    let mut hook_failed = false;
    if all_ok && let Some(cmd) = args.post_dump.as_deref() {
        ui::section("Post-dump hook");
        match run_post_dump(cmd, &out_dir, build_number, args.quiet || args.json) {
            Ok(code) => {
                hook_failed = code != 0;
                hook_json = json!({ "ok": code == 0, "exit": code });
                if hook_failed {
                    ui::err(&format!("hook exited with code {code}"));
                } else {
                    ui::ok("hook finished");
                }
            }
            Err(e) => {
                hook_failed = true;
                hook_json = json!({ "ok": false, "error": format!("{e:#}") });
                ui::err(&format!("hook failed to start: {e:#}"));
            }
        }
    }

    if args.json {
        let names = |f: &dyn Fn(&patterns::PatternHit) -> bool| -> Vec<&str> {
            sig_report
                .as_ref()
                .map(|r| r.hits.iter().filter(|h| f(h)).map(|h| h.name.as_str()).collect())
                .unwrap_or_default()
        };
        let summary = json!({
            "ok": all_ok && !hook_failed,
            "build": build_number,
            "output": std::path::absolute(&out_dir).unwrap_or_else(|_| out_dir.clone()),
            "offsets_ok": offsets_ok,
            "patterns_ok": sigs_ok,
            "checks_ok": checks_ok,
            "patterns": {
                "found": sig_report.as_ref().map(|r| r.found),
                "total": sig_report.as_ref().map(|r| r.total),
                "missing": names(&|h| !h.found),
                "healed": names(&|h| h.healed_from.is_some()),
            },
            "post_dump": hook_json,
        });
        println!("{summary}");
    }

    Ok(if !all_ok {
        1
    } else if hook_failed {
        2
    } else {
        0
    })
}

/// `--only`: scan a handful of patterns against the live process and print
/// the result. Writes nothing and skips the offsets pass.
fn run_only(args: &Args) -> Result<i32> {
    let needles: Vec<String> = args.only.iter().map(|n| n.trim().to_ascii_lowercase()).filter(|n| !n.is_empty()).collect();
    let sigs: Vec<patterns::Pattern> = patterns::database::CS2_PATTERNS
        .iter()
        .filter(|p| {
            let name = p.name.to_ascii_lowercase();
            needles.iter().any(|n| name.contains(n))
        })
        .cloned()
        .collect();
    anyhow::ensure!(!sigs.is_empty(), "no pattern name contains any of {:?}", args.only);

    init_logging(None, args.verbose, args.quiet || args.json)?;
    ui::section("Attach");
    let mut os = build_os(args)?;
    let mut process = os
        .process_by_name(&args.process_name)
        .with_context(|| format!("process '{}' not found", args.process_name))?;
    ui::ok(&format!("attached to {} (pid {})", args.process_name, process.info().pid));

    ui::section(&format!("Probe ({} of {} patterns)", sigs.len(), patterns::database::CS2_PATTERNS.len()));
    let previous = patterns::load_previous(&args.previous.join("patterns").join("patterns.json"));
    let report = patterns::scan_all(&mut process, &sigs, previous.as_ref())?;
    let all_found = report.found == report.total;

    if args.json {
        println!("{}", json!({ "ok": all_found, "found": report.found, "total": report.total, "patterns": report.hits }));
    } else if !args.quiet {
        for h in report.hits.iter().filter(|h| h.found) {
            if let (Some(rva), Some(synth)) = (h.rva, h.pattern_synth.as_deref()) {
                println!("    {} {}+0x{:X}\n      {}", h.name, h.module, rva, synth);
            }
        }
        ui::done(all_found, &format!("{}/{} probed patterns resolved", report.found, report.total));
    }
    Ok(i32::from(!all_found))
}

/// Run the `--post-dump` command through the platform shell and return its
/// exit code. Output goes to stderr in quiet/json mode so stdout stays clean.
fn run_post_dump(cmd: &str, out_dir: &Path, build: Option<u32>, to_stderr: bool) -> Result<i32> {
    use std::process::Command;

    let abs = std::path::absolute(out_dir).unwrap_or_else(|_| out_dir.to_path_buf());
    let line = cmd
        .replace("{out}", &abs.display().to_string())
        .replace("{build}", &build.map(|b| b.to_string()).unwrap_or_else(|| "unknown".into()));

    #[cfg(windows)]
    let output = {
        use std::os::windows::process::CommandExt;
        Command::new("cmd").arg("/C").raw_arg(&line).output()?
    };
    #[cfg(not(windows))]
    let output = Command::new("sh").arg("-c").arg(&line).output()?;

    let text = format!("{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    if to_stderr {
        eprint!("{text}");
    } else {
        print!("{text}");
    }
    Ok(output.status.code().unwrap_or(-1))
}

fn build_os(args: &Args) -> Result<OsInstanceArcBox<'static>> {
    let conn_args = args
        .connector_args
        .as_deref()
        .map(ConnectorArgs::from_str)
        .transpose()
        .map_err(|e| anyhow::anyhow!("invalid connector args: {}", e))?
        .unwrap_or_default();

    match &args.connector {
        Some(conn) => {
            let mut inventory = Inventory::scan();
            Ok(inventory
                .builder()
                .connector(conn)
                .args(conn_args)
                .os("win32")
                .build()?)
        }
        None => {
            #[cfg(windows)]
            {
                Ok(memflow_native::create_os(&OsArgs::default(), LibArc::default())?)
            }
            #[cfg(not(windows))]
            {
                anyhow::bail!("no connector specified and no native backend on this platform")
            }
        }
    }
}

fn init_logging(out_dir: Option<&Path>, verbose: u8, quiet: bool) -> Result<()> {
    let term_level = match verbose {
        _ if quiet => LevelFilter::Error,
        0 => LevelFilter::Warn,
        1 => LevelFilter::Info,
        2 => LevelFilter::Debug,
        _ => LevelFilter::Trace,
    };
    let mut loggers: Vec<Box<dyn SharedLogger>> = Vec::new();
    loggers.push(TermLogger::new(
        term_level,
        Config::default(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    ));
    // File log captures warnings+ only — keeps cs2-sdk.log small and
    // useful for post-mortem instead of being a multi-megabyte trace dump.
    if let Some(out_dir) = out_dir {
        loggers.push(WriteLogger::new(
            LevelFilter::Warn,
            Config::default(),
            File::create(out_dir.join("cs2-sdk.log"))?,
        ));
    }
    CombinedLogger::init(loggers).ok();
    Ok(())
}

/// Names of the major CS2 modules we attached to. Returned as a sorted
/// list for the manifest — consumers don't need per-module fingerprints,
/// `build_number` already disambiguates builds.
fn list_loaded_module_names<P: Process + MemoryView>(
    process: &mut P,
) -> Vec<&'static str> {
    const MODULES: &[&str] = &[
        "client.dll", "engine2.dll", "server.dll", "schemasystem.dll",
        "animationsystem.dll", "materialsystem2.dll", "particles.dll",
        "scenesystem.dll", "soundsystem.dll", "tier0.dll", "vphysics2.dll",
        "networksystem.dll", "host.dll", "panorama.dll",
        "rendersystemdx11.dll", "resourcesystem.dll", "vstdlib.dll",
        "pulse_system.dll", "inputsystem.dll", "filesystem_stdio.dll",
    ];
    MODULES.iter()
        .copied()
        .filter(|name| process.module_by_name(name).is_ok())
        .collect()
}

/// Pretty-print only successfully-resolved patterns, one hit per line.
/// Unfound entries are dropped entirely � they have no usable address.
fn format_found_patterns(report: &patterns::PatternReport) -> String {
    let found: Vec<&patterns::PatternHit> =
        report.hits.iter().filter(|h| h.found).collect();

    let name_w = found.iter().map(|h| h.name.len()).max().unwrap_or(0);
    let mod_w = found.iter().map(|h| h.module.len()).max().unwrap_or(0);
    let res_w = found.iter().map(|h| h.resolve.len()).max().unwrap_or(0);
    let pat_w = found.iter().map(|h| h.pattern.len()).max().unwrap_or(0);
    let byt_w = found
        .iter()
        .map(|h| h.bytes.as_deref().map(|b| b.len() + 2).unwrap_or(6))
        .max()
        .unwrap_or(6);
    let synth_w = found
        .iter()
        .map(|h| h.pattern_synth.as_deref().map(|b| b.len() + 2).unwrap_or(6))
        .max()
        .unwrap_or(6);
    let proto_w = found
        .iter()
        .map(|h| h.prototype.as_deref().map(|b| b.len() + 2).unwrap_or(6))
        .max()
        .unwrap_or(6);

    let mut s = String::new();
    s.push_str("{\n");
    s.push_str(&format!("  \"total_scanned\":  {},\n", report.total));
    s.push_str(&format!("  \"found\":          {},\n", report.found));
    s.push_str(&format!("  \"unique_functions\": {},\n", report.unique_functions));
    s.push_str(&format!("  \"missing\":        {},\n", report.total - report.found));

    s.push_str(&format!(
        "  \"modules\":        [{}],\n",
        report
            .modules
            .iter()
            .map(|m| format!("\"{}\"", m))
            .collect::<Vec<_>>()
            .join(", ")
    ));
    s.push_str("  \"patterns\": [\n");
    for (i, h) in found.iter().enumerate() {
        let comma = if i + 1 == found.len() { "" } else { "," };
        let va = h.va.map(|v| format!("\"0x{:X}\"", v)).unwrap_or_else(|| "null".into());
        let rva = h.rva.map(|v| format!("\"0x{:X}\"", v)).unwrap_or_else(|| "null".into());
        let bytes_field = h
            .bytes
            .as_deref()
            .map(|b| format!("\"{}\"", b))
            .unwrap_or_else(|| "null".into());
        let synth_field = h
            .pattern_synth
            .as_deref()
            .map(|b| format!("\"{}\"", b))
            .unwrap_or_else(|| "null".into());
        let proto_field = h
            .prototype
            .as_deref()
            .map(|b| format!("\"{}\"", b.replace('\\', "\\\\").replace('"', "\\\"")))
            .unwrap_or_else(|| "\"\"".into());
        let healed_field = h
            .healed_from
            .as_deref()
            .map(|p| format!(", \"healed_from\": \"{}\"", p))
            .unwrap_or_default();
        let alias_field = if h.aliases.is_empty() {
            String::new()
        } else {
            format!(", \"aliases\": [{}]", h.aliases.iter().map(|a| format!("\"{}\"", a)).collect::<Vec<_>>().join(", "))
        };
        s.push_str(&format!(
            "    {{ \"name\": {:<nw$}, \"module\": {:<mw$}, \"resolve\": {:<rw$}, \"va\": {:>16}, \"rva\": {:>12}, \"pattern\": {:<pw$}, \"bytes\": {:<bw$}, \"pattern_synth\": {:<sw$}, \"prototype\": {:<pxw$}{}{} }}{}\n",
            format!("\"{}\"", h.name),
            format!("\"{}\"", h.module),
            format!("\"{}\"", h.resolve),
            va,
            rva,
            format!("\"{}\"", h.pattern),
            bytes_field,
            synth_field,
            proto_field,
            alias_field,
            healed_field,
            comma,
            nw = name_w + 2,
            mw = mod_w + 2,
            rw = res_w + 2,
            pw = pat_w + 2,
            bw = byt_w,
            sw = synth_w,
            pxw = proto_w,
        ));
    }
    s.push_str("  ]\n");
    s.push_str("}\n");
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn post_dump_substitutes_placeholders_and_returns_exit_code() {
        let dir = std::env::temp_dir();
        // `exit N` works in both `cmd /C` and `sh -c`.
        assert_eq!(run_post_dump("exit 0", &dir, Some(14184), true).unwrap(), 0);
        assert_eq!(run_post_dump("exit 3", &dir, None, true).unwrap(), 3);
    }

    #[test]
    fn post_dump_expands_build_placeholder() {
        let dir = std::env::temp_dir();
        // Succeeds only when `{build}` was replaced by the real number.
        #[cfg(windows)]
        let cmd = "if \"{build}\"==\"14184\" (exit 0) else (exit 9)";
        #[cfg(not(windows))]
        let cmd = "[ \"{build}\" = 14184 ]";
        assert_eq!(run_post_dump(cmd, &dir, Some(14184), true).unwrap(), 0);
        assert_ne!(run_post_dump(cmd, &dir, Some(1), true).unwrap(), 0);
    }

    #[test]
    fn post_dump_expands_out_placeholder() {
        let dir = std::env::temp_dir();
        // `dir "<out>"` / `test -d` fail unless {out} is a real absolute directory.
        #[cfg(windows)]
        let cmd = "cd /d \"{out}\"";
        #[cfg(not(windows))]
        let cmd = "test -d \"{out}\"";
        assert_eq!(run_post_dump(cmd, &dir, None, true).unwrap(), 0);
    }
}
