use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use clap::Parser;
use csv::Writer;
use futures::future::join_all;
use regex::Regex;
use reqwest::Client;
use scraper::{Html, Selector};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Semaphore};
use url::Url;

#[derive(Parser)]
#[command(name = "js-hunter")]
#[command(about = "A fast JavaScript file hunter and secret scanner")]
struct Args {
    #[arg(long, help = "File containing URLs (one per line)")]
    urls: PathBuf,
    
    #[arg(long, help = "Output directory")]
    output: PathBuf,
    
    #[arg(long, default_value = "50", help = "Number of concurrent workers")]
    workers: usize,
    
    #[arg(long, help = "JSON file containing regex patterns")]
    patterns: PathBuf,
}

#[derive(Debug, Serialize, Deserialize)]
struct PatternConfig {
    patterns: HashMap<String, PatternInfo>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PatternInfo {
    regex: String,
    description: String,
}

#[derive(Debug, Clone)]
struct CompiledPattern {
    name: String,
    regex: Regex,
    description: String,
}

#[derive(Debug, Serialize)]
struct CSVRecord {
    url: String,
    js_path: String,
    filename: String,
    hash: String,
    status: u16,
    secrets_found: bool,
    regex_matches: String,
    file_size: Option<usize>,
    fetch_time: String,
}

#[derive(Debug)]
struct WorkerStats {
    processed_urls: AtomicUsize,
    js_files_found: AtomicUsize,
    secrets_found: AtomicUsize,
    active_workers: AtomicUsize,
}

struct JSHunter {
    client: Client,
    patterns: Vec<CompiledPattern>,
    output_dir: PathBuf,
    js_files_dir: PathBuf,
    seen_hashes: Arc<tokio::sync::Mutex<HashSet<String>>>,
}

impl JSHunter {
    fn new(output_dir: PathBuf, patterns: Vec<CompiledPattern>) -> Result<Self> {
        let js_files_dir = output_dir.join("js_files");
        fs::create_dir_all(&js_files_dir)
            .context("Failed to create js_files directory")?;

        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            // Maybe we use something else?
            .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
            .build()?;

        Ok(Self {
            client,
            patterns,
            output_dir,
            js_files_dir,
            seen_hashes: Arc::new(tokio::sync::Mutex::new(HashSet::new())),
        })
    }

    async fn process_url(&self, url: String) -> Vec<CSVRecord> {
        let mut records = Vec::new();
        
        let page_response = match self.client.get(&url).send().await {
            Ok(response) => response,
            Err(_) => {
                records.push(CSVRecord {
                    url,
                    js_path: "".to_string(),
                    filename: "".to_string(),
                    hash: "".to_string(),
                    status: 0,
                    secrets_found: false,
                    regex_matches: "".to_string(),
                    file_size: None,
                    fetch_time: Utc::now().to_rfc3339(),
                });
                return records;
            }
        };

        let status = page_response.status().as_u16();
        if !page_response.status().is_success() {
            records.push(CSVRecord {
                url,
                js_path: "".to_string(),
                filename: "".to_string(),
                hash: "".to_string(),
                status,
                secrets_found: false,
                regex_matches: "".to_string(),
                file_size: None,
                fetch_time: Utc::now().to_rfc3339(),
            });
            return records;
        }

        let html = match page_response.text().await {
            Ok(html) => html,
            Err(_) => return records,
        };

        let js_urls = self.extract_js_urls(&url, &html);
        
        for js_url in js_urls {
            let record = self.process_js_file(&url, &js_url).await;
            records.push(record);
        }

        records
    }

    fn extract_js_urls(&self, base_url: &str, html: &str) -> Vec<String> {
        let document = Html::parse_document(html);
        let selector = Selector::parse("script[src]").unwrap();
        let mut js_urls = Vec::new();

        let base = match Url::parse(base_url) {
            Ok(url) => url,
            Err(_) => return js_urls,
        };

        for element in document.select(&selector) {
            if let Some(src) = element.value().attr("src") {
                if src.ends_with(".js") {
                    match base.join(src) {
                        Ok(absolute_url) => js_urls.push(absolute_url.to_string()),
                        Err(_) => continue,
                    }
                }
            }
        }

        js_urls
    }

    async fn process_js_file(&self, source_url: &str, js_url: &str) -> CSVRecord {
        let fetch_time = Utc::now().to_rfc3339();
        let filename = self.extract_filename(js_url);

        let js_response = match self.client.get(js_url).send().await {
            Ok(response) => response,
            Err(_) => {
                return CSVRecord {
                    url: source_url.to_string(),
                    js_path: js_url.to_string(),
                    filename,
                    hash: "".to_string(),
                    status: 0,
                    secrets_found: false,
                    regex_matches: "".to_string(),
                    file_size: None,
                    fetch_time,
                };
            }
        };

        let status = js_response.status().as_u16();
        if !js_response.status().is_success() {
            return CSVRecord {
                url: source_url.to_string(),
                js_path: js_url.to_string(),
                filename,
                hash: "".to_string(),
                status,
                secrets_found: false,
                regex_matches: "".to_string(),
                file_size: None,
                fetch_time,
            };
        }

        let content = match js_response.bytes().await {
            Ok(content) => content,
            Err(_) => {
                return CSVRecord {
                    url: source_url.to_string(),
                    js_path: js_url.to_string(),
                    filename,
                    hash: "".to_string(),
                    status: 0,
                    secrets_found: false,
                    regex_matches: "".to_string(),
                    file_size: None,
                    fetch_time,
                };
            }
        };

        let file_size = content.len();
        let hash = format!("{:x}", Sha256::digest(&content));

        {
            let mut seen_hashes = self.seen_hashes.lock().await;
            if !seen_hashes.contains(&hash) {
                seen_hashes.insert(hash.clone());
                let file_path = self.js_files_dir.join(format!("{}.js", hash));
                let _ = fs::write(file_path, &content);
            }
        }

        let content_str = String::from_utf8_lossy(&content);
        let (secrets_found, matches) = self.scan_for_secrets(&content_str);

        CSVRecord {
            url: source_url.to_string(),
            js_path: js_url.to_string(),
            filename,
            hash,
            status,
            secrets_found,
            regex_matches: matches.join(","),
            file_size: Some(file_size),
            fetch_time,
        }
    }

    fn extract_filename(&self, url: &str) -> String {
        if let Ok(parsed_url) = Url::parse(url) {
            if let Some(path_segments) = parsed_url.path_segments() {
                if let Some(filename) = path_segments.last() {
                    return filename.to_string();
                }
            }
        }
        "unknown.js".to_string()
    }

    fn scan_for_secrets(&self, content: &str) -> (bool, Vec<String>) {
        let mut matches = Vec::new();
        
        for pattern in &self.patterns {
            if pattern.regex.is_match(content) {
                matches.push(pattern.name.clone());
            }
        }

        (!matches.is_empty(), matches)
    }
}

fn load_patterns(patterns_file: &Path) -> Result<Vec<CompiledPattern>> {
    let content = fs::read_to_string(patterns_file)
        .context("Failed to read patterns file")?;
    
    let config: PatternConfig = serde_json::from_str(&content)
        .context("Failed to parse patterns JSON")?;

    let mut compiled_patterns = Vec::new();
    for (name, info) in config.patterns {
        match Regex::new(&info.regex) {
            Ok(regex) => {
                compiled_patterns.push(CompiledPattern {
                    name,
                    regex,
                    description: info.description,
                });
            }
            Err(e) => {
                eprintln!("Warning: Failed to compile regex for pattern '{}': {}", name, e);
            }
        }
    }

    Ok(compiled_patterns)
}

fn load_urls(urls_file: &Path) -> Result<Vec<String>> {
    let content = fs::read_to_string(urls_file)
        .context("Failed to read URLs file")?;
    
    let urls: Vec<String> = content
        .lines()
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty())
        .collect();

    Ok(urls)
}

async fn print_progress(stats: Arc<WorkerStats>) {
    let mut interval = tokio::time::interval(Duration::from_secs(60));
    loop {
        interval.tick().await;
        let processed = stats.processed_urls.load(Ordering::Relaxed);
        let js_files = stats.js_files_found.load(Ordering::Relaxed);
        let secrets = stats.secrets_found.load(Ordering::Relaxed);
        let active = stats.active_workers.load(Ordering::Relaxed);
        
        println!(
            "[{}] Processed: {} URLs | JS Files: {} | Secrets Found: {} | Workers Active: {}",
            Utc::now().format("%Y-%m-%d %H:%M:%S"),
            processed,
            js_files,
            secrets,
            active
        );
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    fs::create_dir_all(&args.output)
        .context("Failed to create output directory")?;

    println!("Loading patterns from: {:?}", args.patterns);
    let patterns = load_patterns(&args.patterns)?;
    println!("Loaded {} patterns", patterns.len());

    println!("Loading URLs from: {:?}", args.urls);
    let urls = load_urls(&args.urls)?;
    println!("Loaded {} URLs", urls.len());

    let hunter = Arc::new(JSHunter::new(args.output.clone(), patterns)?);
    let semaphore = Arc::new(Semaphore::new(args.workers));
    let stats = Arc::new(WorkerStats {
        processed_urls: AtomicUsize::new(0),
        js_files_found: AtomicUsize::new(0),
        secrets_found: AtomicUsize::new(0),
        active_workers: AtomicUsize::new(0),
    });

    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<CSVRecord>>();

    let progress_stats = Arc::clone(&stats);
    let progress_task = tokio::spawn(print_progress(progress_stats));

    let start_time = Instant::now();
    println!("Starting scan with {} workers...", args.workers);

    let worker_tasks: Vec<_> = urls
        .into_iter()
        .map(|url| {
            let hunter = Arc::clone(&hunter);
            let semaphore = Arc::clone(&semaphore);
            let stats = Arc::clone(&stats);
            let tx = tx.clone();

            tokio::spawn(async move {
                let _permit = semaphore.acquire().await.unwrap();
                stats.active_workers.fetch_add(1, Ordering::Relaxed);

                let records = hunter.process_url(url).await;
                let js_count = records.len();
                let secrets_count = records.iter().filter(|r| r.secrets_found).count();

                stats.processed_urls.fetch_add(1, Ordering::Relaxed);
                stats.js_files_found.fetch_add(js_count, Ordering::Relaxed);
                stats.secrets_found.fetch_add(secrets_count, Ordering::Relaxed);
                stats.active_workers.fetch_sub(1, Ordering::Relaxed);

                let _ = tx.send(records);
            })
        })
        .collect();

    drop(tx);

    let mut all_records = Vec::new();
    while let Some(records) = rx.recv().await {
        all_records.extend(records);
    }

    join_all(worker_tasks).await;
    progress_task.abort();

    let csv_path = args.output.join("scan_results.csv");
    let mut writer = Writer::from_path(&csv_path)?;

    for record in &all_records {
        writer.serialize(record)?;
    }
    writer.flush()?;

    let elapsed = start_time.elapsed();
    let total_urls = stats.processed_urls.load(Ordering::Relaxed);
    let total_js = stats.js_files_found.load(Ordering::Relaxed);
    let total_secrets = stats.secrets_found.load(Ordering::Relaxed);

    println!("\n=== Scan Complete ===");
    println!("Total time: {:.2} seconds", elapsed.as_secs_f64());
    println!("URLs processed: {}", total_urls);
    println!("JS files found: {}", total_js);
    println!("Files with secrets: {}", total_secrets);
    println!("Results saved to: {:?}", csv_path);
    println!("JS files saved to: {:?}", hunter.js_files_dir);

    Ok(())
}
