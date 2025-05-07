import requests
import csv
import json
import time
import os
import re
import glob
import toml
from packaging.version import Version, parse
from typing import Tuple, List, Dict, Any, Optional
from urllib.parse import quote

OSV_API_URL = "https://api.osv.dev/v1/query"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Manifest patterns for different ecosystems
MANIFEST_PATTERNS = {
    "pypi": ["requirements.txt", "setup.py", "pyproject.toml", "Pipfile", "poetry.lock"],
    "npm": ["package.json", "yarn.lock", "package-lock.json", "npm-shrinkwrap.json"],
    "maven": ["pom.xml", "build.gradle", "build.gradle.kts"],
    "nuget": ["*.csproj", "packages.config", "*.fsproj", "*.vbproj", "project.json"]
}

def normalize_license(license_info: str) -> str:
    """Normalize license information to a standard format."""
    if not license_info or license_info.lower() in ['unknown', 'none', 'null', '']:
        return "Unknown"
    
    # Remove common unnecessary prefixes/suffixes
    license_info = license_info.strip().replace('License:', '').strip()
    
    # Map common license variations to standard SPDX identifiers
    license_map = {
        'mit': 'MIT',
        'apache 2': 'Apache-2.0',
        'apache2': 'Apache-2.0',
        'apache-2': 'Apache-2.0',
        'apache 2.0': 'Apache-2.0',
        'gpl': 'GPL-3.0',
        'gpl-3': 'GPL-3.0',
        'gpl3': 'GPL-3.0',
        'lgpl': 'LGPL-3.0',
        'bsd': 'BSD-3-Clause',
        'isc': 'ISC'
    }
    
    normalized = license_map.get(license_info.lower(), license_info)
    return normalized

def safe_version_parse(version_str: str) -> Optional[Version]:
    """Safely parse version string to Version object."""
    try:
        return parse(version_str) if version_str and version_str != "Unknown" else None
    except Exception:
        return None

def fetch_latest_version(package_name: str, registry: str) -> str:
    """Fetch the latest available version of a package from the registry."""
    urls = {
        "pypi": f"https://pypi.org/pypi/{quote(package_name)}/json",
        "npm": f"https://registry.npmjs.org/{quote(package_name)}",
        "maven": f"https://search.maven.org/solrsearch/select?q=g:{quote(package_name)}&rows=1&wt=json",
        "nuget": f"https://api.nuget.org/v3/registration5-gz-semver2/{quote(package_name.lower())}/index.json"
    }
    
    url = urls.get(registry)
    if not url:
        return "Unknown"

    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()

        if registry == "pypi":
            return data.get("info", {}).get("version", "Unknown")
        elif registry == "npm":
            return data.get("dist-tags", {}).get("latest", "Unknown")
        elif registry == "maven":
            docs = data.get("response", {}).get("docs", [])
            return docs[0].get("latestVersion", "Unknown") if docs else "Unknown"
        elif registry == "nuget":
            items = data.get("items", [])
            return items[-1].get("upper", "Unknown") if items else "Unknown"

        return "Unknown"

    except requests.exceptions.RequestException as e:
        print(f"⚠️ Error fetching latest version for {package_name}: {str(e)}")
        return "Unknown"

def fetch_license_info(package_name: str, registry: str) -> str:
    """Fetch license information for a package from the registry."""
    urls = {
        "pypi": f"https://pypi.org/pypi/{quote(package_name)}/json",
        "npm": f"https://registry.npmjs.org/{quote(package_name)}",
        "maven": f"https://search.maven.org/solrsearch/select?q=g:{quote(package_name)}&rows=1&wt=json",
        "nuget": f"https://api.nuget.org/v3/registration5-gz-semver2/{quote(package_name.lower())}/index.json"
    }
    url = urls.get(registry)
    if not url:
        return "Unknown"
    
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()

        if registry == "pypi":
            license_info = data.get("info", {}).get("license", "Unknown")
            if license_info == "Unknown":
                # Check classifiers for license info
                for classifier in data.get("info", {}).get("classifiers", []):
                    if classifier.startswith("License ::"):
                        license_info = classifier.split("::")[-1].strip()
                        break
        elif registry == "npm":
            license_info = data.get("license", "Unknown")
            if isinstance(license_info, dict):
                license_info = license_info.get("type", "Unknown")
        elif registry == "maven":
            license_info = "Check project repository"  # Maven API does not provide license info
        elif registry == "nuget":
            license_info = data.get("licenseExpression", data.get("license", {}).get("type", "Unknown"))
        else:
            license_info = "Unknown"

        return normalize_license(license_info)
    except requests.exceptions.RequestException as e:
        print(f"⚠️ Error fetching license info for {package_name}: {str(e)}")
        return "Unknown"

def get_safe_versions(vuln: Dict[str, Any], current_version: str, latest_version: str) -> List[str]:
    """Find safe versions that are newer than the current version."""
    if not current_version or current_version == "Unknown":
        return ["Update to latest version"]
    
    current_ver = safe_version_parse(current_version)
    if not current_ver:
        return ["Version parsing error"]
    
    safe_versions = set()
    fixed_versions = set()
    
    for affected in vuln.get("affected", []):
        for range_obj in affected.get("ranges", []):
            if range_obj.get("type") == "SEMVER":
                for event in range_obj.get("events", []):
                    if "fixed" in event:
                        fixed_versions.add(event["fixed"])
    
    fixed_versions = {v for v in fixed_versions if safe_version_parse(v)}
    valid_versions = sorted(fixed_versions, key=lambda x: safe_version_parse(x))
    
    for ver in valid_versions:
        if safe_version_parse(ver) > current_ver:
            safe_versions.add(ver)
    
    if not safe_versions and latest_version != "Unknown":
        latest_ver = safe_version_parse(latest_version)
        if latest_ver and latest_ver > current_ver:
            safe_versions.add(latest_version)
    
    return sorted(safe_versions, key=lambda x: safe_version_parse(x)) if safe_versions else ["No known safe version"]

def get_cvss_severity(cve_id: str) -> Dict[str, Any]:
    """Fetch CVSS data from NVD for a given CVE ID."""
    if not cve_id.startswith("CVE-"):
        return {
            "score": "N/A",
            "severity": "Unknown",
            "vector": "N/A",
            "version": "N/A"
        }
    
    try:
        time.sleep(0.6)
        headers = {"User-Agent": "SecurityScanner/1.0"}
        params = {"cveId": cve_id}
        
        response = requests.get(NVD_API_URL, params=params, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()
        
        if not data.get("vulnerabilities"):
            return {
                "score": "N/A",
                "severity": "Unknown",
                "vector": "N/A",
                "version": "N/A"
            }
        
        metrics = data["vulnerabilities"][0]["cve"]["metrics"]
        if "cvssMetricV31" in metrics:
            cvss = metrics["cvssMetricV31"][0]
            version_cvss = "3.1"
        elif "cvssMetricV30" in metrics:
            cvss = metrics["cvssMetricV30"][0]
            version_cvss = "3.0"
        elif "cvssMetricV2" in metrics:
            cvss = metrics["cvssMetricV2"][0]
            version_cvss = "2.0"
        else:
            return {
                "score": "N/A",
                "severity": "Unknown",
                "vector": "N/A",
                "version": "N/A"
            }
        
        base_score = cvss.get("cvssData", {}).get("baseScore", "N/A")
        severity = cvss.get("cvssData", {}).get("baseSeverity", "Unknown")
        vector = cvss.get("cvssData", {}).get("vectorString", "N/A")
        
        return {
            "score": str(base_score),
            "severity": severity,
            "vector": vector,
            "version": version_cvss
        }
        
    except requests.exceptions.RequestException as e:
        print(f"⚠️ Error fetching CVSS data for {cve_id}: {str(e)}")
        return {
            "score": "N/A",
            "severity": "Unknown",
            "vector": "N/A",
            "version": "N/A"
        }

def check_osv_vulnerabilities(package: str, version: str, ecosystem: str, latest_version: str) -> List[Dict[str, Any]]:
    """Check for vulnerabilities using the OSV API and fetch CVSS scores from NVD."""
    if not version or version == "Unknown":
        return [{"error": "Invalid version"}]

    query = {
        "package": {"name": package, "ecosystem": ecosystem},
        "version": version
    }
    
    try:
        response = requests.post(OSV_API_URL, json=query, timeout=10)
        response.raise_for_status()
        data = response.json()
    except requests.exceptions.RequestException as e:
        return [{"error": f"OSV API error: {str(e)}"}]
    
    vulnerabilities = []
    for vuln in data.get("vulns", []):
        cve_id = next((alias for alias in vuln.get("aliases", []) if alias.startswith("CVE")), vuln["id"])
        cvss_data = get_cvss_severity(cve_id) if cve_id.startswith("CVE-") else {
            "score": "N/A",
            "severity": "Unknown",
            "vector": "N/A",
            "version": "N/A"
        }
        
        safe_versions = get_safe_versions(vuln, version, latest_version)
        
        vulnerabilities.append({
            "id": cve_id,
            "details": f"{cve_id} - {vuln.get('summary', 'No summary available')}",
            "cvss": cvss_data,
            "safe_versions": safe_versions,
            "modified": vuln.get("modified", "Unknown")
        })
    
    return vulnerabilities

def check_packages(batch_packages: List[Tuple[str, str, str]]) -> List[Dict[str, Any]]:
    """Check multiple packages for vulnerabilities, license information, and version details."""
    results = []
    for package, version, registry in batch_packages:
        latest_version = fetch_latest_version(package, registry)
        # If user didn't supply a version, default to latest.
        if not version or version == "Unknown":
            version = latest_version
        
        ecosystem_map = {
            "pypi": "PyPI",
            "npm": "npm",
            "maven": "Maven",
            "nuget": "NuGet"
        }
        ecosystem = ecosystem_map.get(registry.lower(), registry.lower())
        vulnerabilities = check_osv_vulnerabilities(package, version, ecosystem, latest_version)
        safe_versions = set()
        for vuln in vulnerabilities:
            if "safe_versions" in vuln:
                safe_versions.update(vuln["safe_versions"])
        
        license_info = fetch_license_info(package, registry)
        
        result = {
            "package": package,
            "version": version,
            "registry": registry.capitalize(),
            "latest_version": latest_version,
            "license": license_info,
            "vulnerabilities": vulnerabilities if vulnerabilities else [],
            "safe_versions": list(safe_versions) if safe_versions else ["No issues detected"],
            "recommendation": f"Update available: {latest_version}" if latest_version != "Unknown" and version != latest_version else "Up-to-date"
        }
        results.append(result)
    return results

def write_results_to_csv(results: List[Dict[str, Any]], output_file: str = "vulnerability_report.csv") -> None:
    """Write results to a CSV file with enhanced formatting."""
    with open(output_file, "w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        headers = [
            "Package", "Version", "Registry", "Latest Version",
            "License", "Vulnerabilities", "CVSS Score", "CVSS Severity", "CVSS Vector",
            "Safe Versions", "Recommendation", "Source File"
        ]
        writer.writerow(headers)
        
        for result in results:
            vulns = []
            cvss_scores = []
            cvss_severities = []
            cvss_vectors = []
            safe_versions = []
            
            for vuln in result.get("vulnerabilities", []):
                if "error" not in vuln:
                    vulns.append(vuln["details"])
                    cvss_scores.append(vuln["cvss"]["score"])
                    cvss_severities.append(vuln["cvss"]["severity"])
                    cvss_vectors.append(vuln["cvss"]["vector"])
                    safe_versions.extend(vuln["safe_versions"])
            
            writer.writerow([
                result["package"],
                result["version"],
                result["registry"],
                result.get("latest_version", "Unknown"),
                result.get("license", "Unknown"),
                " | ".join(vulns) if vulns else "None",
                " | ".join(cvss_scores) if cvss_scores else "N/A",
                " | ".join(cvss_severities) if cvss_severities else "N/A",
                " | ".join(cvss_vectors) if cvss_vectors else "N/A",
                " | ".join(set(safe_versions)) if safe_versions else "N/A",
                result.get("recommendation", "-"),
                result.get("source_file", "-")
            ])

def parse_requirements_txt(file_path: str) -> List[Tuple[str, str]]:
    """Parse Python requirements.txt file to extract package names and versions."""
    dependencies = []
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            for line in file:
                line = line.strip()
                # Skip comments and empty lines
                if not line or line.startswith('#'):
                    continue
                
                # Handle case where line might have a comment after the requirement
                line = line.split('#')[0].strip()
                
                # Skip editable installs for now
                if line.startswith('-e '):
                    continue
                
                # Skip options
                if line.startswith('-'):
                    continue
                
                # Handle URL or path installs with egg fragment (e.g., git+https://...)
                if 'egg=' in line:
                    egg_fragment = re.search(r'egg=([^&]+)', line)
                    if egg_fragment:
                        package = egg_fragment.group(1)
                        dependencies.append((package, "Unknown"))
                    continue
                
                # Regular package requirement (e.g., package==1.0.0, package>=1.0.0)
                package_match = re.match(r'^([^<>=~!]+)(.*)', line)
                if package_match:
                    package = package_match.group(1).strip()
                    version_spec = package_match.group(2).strip()
                    
                    # Extract exact version if possible
                    version = "Unknown"
                    if '==' in version_spec:
                        version = version_spec.split('==')[1].strip()
                    elif '@' in line:
                        # Handle PEP 440 direct references (pkg @ file://)
                        parts = line.split('@', 1)
                        package = parts[0].strip()
                    
                    dependencies.append((package, version))
                    
    except Exception as e:
        print(f"Error parsing {file_path}: {str(e)}")
    
    return dependencies

def parse_setup_py(file_path: str) -> List[Tuple[str, str]]:
    """Parse Python setup.py file to extract package dependencies."""
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            content = file.read()
        
        install_requires = re.search(r'install_requires\s*=\s*\[(.*?)\]', content, re.DOTALL)
        if not install_requires:
            return []
        
        deps_str = install_requires.group(1)
        # Extract quoted strings
        deps = re.findall(r'[\'"]([^\'"]+)[\'"]', deps_str)
        
        dependencies = []
        for dep in deps:
            # Parse each dependency string similar to requirements.txt
            package_match = re.match(r'^([^<>=~!]+)(.*)', dep)
            if package_match:
                package = package_match.group(1).strip()
                version_spec = package_match.group(2).strip()
                
                # Extract exact version if possible
                version = "Unknown"
                if '==' in version_spec:
                    version = version_spec.split('==')[1].strip()
                
                dependencies.append((package, version))
        
        return dependencies
    except Exception as e:
        print(f"Error parsing {file_path}: {str(e)}")
        return []

def parse_pyproject_toml(file_path: str) -> List[Tuple[str, str]]:
    """Parse pyproject.toml file to extract package dependencies."""
    try:
        data = toml.load(file_path)
        dependencies = []
        
        # Check for dependencies in [project] section (PEP 621)
        if "project" in data and "dependencies" in data["project"]:
            deps = data["project"]["dependencies"]
            for dep in deps:
                package_match = re.match(r'^([^<>=~!]+)(.*)', dep)
                if package_match:
                    package = package_match.group(1).strip()
                    version_spec = package_match.group(2).strip()
                    
                    # Extract exact version if possible
                    version = "Unknown"
                    if '==' in version_spec:
                        version = version_spec.split('==')[1].strip()
                    
                    dependencies.append((package, version))
        
        # Check for poetry dependencies
        if "tool" in data and "poetry" in data["tool"] and "dependencies" in data["tool"]["poetry"]:
            deps = data["tool"]["poetry"]["dependencies"]
            for package, value in deps.items():
                if package == "python":  # Skip python requirement
                    continue
                
                version = "Unknown"
                if isinstance(value, str):
                    version = value
                elif isinstance(value, dict) and "version" in value:
                    version = value["version"]
                
                # Clean up version (remove ^, ~, etc.)
                if version != "Unknown":
                    version = re.sub(r'^[\^~]=?', '', version)
                
                dependencies.append((package, version))
        
        return dependencies
    except Exception as e:
        print(f"Error parsing {file_path}: {str(e)}")
        return []

def parse_package_json(file_path: str) -> List[Tuple[str, str]]:
    """Parse package.json file to extract npm dependencies."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        dependencies = []
        
        # Check standard dependencies
        for dep_type in ["dependencies", "devDependencies"]:
            if dep_type in data:
                for package, version in data[dep_type].items():
                    # Clean up version (remove ^, ~, etc.)
                    clean_version = re.sub(r'^[\^~]=?', '', version)
                    dependencies.append((package, clean_version))
        
        return dependencies
    except Exception as e:
        print(f"Error parsing {file_path}: {str(e)}")
        return []

def parse_pom_xml(file_path: str) -> List[Tuple[str, str]]:
    """Parse Maven pom.xml file to extract dependencies."""
    try:
        import xml.etree.ElementTree as ET
        
        # XML namespace mapping
        ns = {"maven": "http://maven.apache.org/POM/4.0.0"}
        
        tree = ET.parse(file_path)
        root = tree.getroot()
        
        dependencies = []
        
        # Find dependencies in <dependencies> section
        for dep in root.findall(".//maven:dependencies/maven:dependency", ns):
            group_id = dep.find("maven:groupId", ns)
            artifact_id = dep.find("maven:artifactId", ns)
            version = dep.find("maven:version", ns)
            
            if group_id is not None and artifact_id is not None:
                group_id_text = group_id.text
                artifact_id_text = artifact_id.text
                version_text = version.text if version is not None else "Unknown"
                
                # Use the format groupId:artifactId for Maven packages
                package = f"{group_id_text}:{artifact_id_text}"
                dependencies.append((package, version_text))
        
        return dependencies
    except Exception as e:
        print(f"Error parsing {file_path}: {str(e)}")
        return []

def parse_csproj(file_path: str) -> List[Tuple[str, str]]:
    """Parse .NET project file (.csproj, .fsproj, etc.) to extract NuGet package references."""
    try:
        import xml.etree.ElementTree as ET
        
        tree = ET.parse(file_path)
        root = tree.getroot()
        
        dependencies = []
        
        # Look for PackageReference elements
        package_refs = root.findall(".//*[@Include]") + root.findall(".//*[@Include]")
        
        for ref in package_refs:
            if ref.tag.endswith('PackageReference'):
                package = ref.attrib.get('Include')
                version = ref.attrib.get('Version', "Unknown")
                
                if package:
                    dependencies.append((package, version))
        
        return dependencies
    except Exception as e:
        print(f"Error parsing {file_path}: {str(e)}")
        return []

def find_manifest_files(folder_path: str) -> Dict[str, List[str]]:
    """Find all dependency manifest files in the given folder recursively."""
    manifest_files = {registry: [] for registry in MANIFEST_PATTERNS.keys()}
    
    for root, _, files in os.walk(folder_path):
        for registry, patterns in MANIFEST_PATTERNS.items():
            for pattern in patterns:
                # Handle glob patterns
                if '*' in pattern:
                    matches = glob.glob(os.path.join(root, pattern))
                    for match in matches:
                        manifest_files[registry].append(match)
                # Handle exact filenames
                elif pattern in files:
                    manifest_files[registry].append(os.path.join(root, pattern))
    
    return manifest_files

def parse_manifest_file(file_path: str, registry: str) -> List[Tuple[str, str]]:
    """Parse a manifest file based on its type and extract dependencies."""
    file_name = os.path.basename(file_path).lower()
    
    if registry == "pypi":
        if file_name == "requirements.txt":
            return parse_requirements_txt(file_path)
        elif file_name == "setup.py":
            return parse_setup_py(file_path)
        elif file_name == "pyproject.toml":
            return parse_pyproject_toml(file_path)
        # Other Python manifest files...
        
    elif registry == "npm":
        if file_name == "package.json":
            return parse_package_json(file_path)
        # Other NPM manifest files...
        
    elif registry == "maven":
        if file_name == "pom.xml":
            return parse_pom_xml(file_path)
        # Other Maven manifest files...
        
    elif registry == "nuget":
        if file_name.endswith(".csproj") or file_name.endswith(".fsproj") or file_name.endswith(".vbproj"):
            return parse_csproj(file_path)
        # Other .NET manifest files...
    
    return []

def scan_folder(folder_path: str) -> List[Dict[str, Any]]:
    """Scan a folder for dependencies and check their security."""
    if not os.path.isdir(folder_path):
        print(f"Error: {folder_path} is not a valid directory.")
        return []
    
    print(f"Scanning folder: {folder_path}")
    manifest_files = find_manifest_files(folder_path)
    
    all_dependencies = []
    for registry, files in manifest_files.items():
        for file_path in files:
            print(f"Parsing {registry} manifest: {file_path}")
            dependencies = parse_manifest_file(file_path, registry)
            
            for package, version in dependencies:
                all_dependencies.append({
                    "package": package,
                    "version": version,
                    "registry": registry,
                    "source_file": file_path
                })
    
    # De-duplicate dependencies (prefer specific versions over Unknown)
    unique_deps = {}
    for dep in all_dependencies:
        key = f"{dep['package']}:{dep['registry']}"
        if key not in unique_deps or dep['version'] != "Unknown":
            unique_deps[key] = dep
    
    batch_packages = [(dep["package"], dep["version"], dep["registry"]) for dep in unique_deps.values()]
    
    print(f"Found {len(batch_packages)} unique dependencies. Checking security...")
    results = check_packages(batch_packages)
    
    # Add source file information to results
    for result in results:
        package_key = f"{result['package']}:{result['registry'].lower()}"
        if package_key in unique_deps:
            result["source_file"] = unique_deps[package_key]["source_file"]
    
    return results

def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description="SCA Scanner - Software Composition Analysis Tool",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    # Add mode as a subcommand
    subparsers = parser.add_subparsers(dest="mode", help="Scan mode")
    
    # Single package mode
    single_parser = subparsers.add_parser("single", help="Scan a single package")
    single_parser.add_argument("--package", "-p", required=True, help="Package name")
    single_parser.add_argument("--version", "-v", default="", help="Package version (leave empty for latest)")
    single_parser.add_argument("--registry", "-r", required=True, choices=["pypi", "npm", "maven", "nuget"], 
                              help="Package registry")
    single_parser.add_argument("--output", "-o", default="vulnerability_report.json", 
                              help="Output file path (default: vulnerability_report.json)")
    single_parser.add_argument("--format", "-f", choices=["json", "csv"], default="json",
                              help="Output format (default: json)")
    
    # Batch mode
    batch_parser = subparsers.add_parser("batch", help="Scan multiple packages from a CSV file")
    batch_parser.add_argument("--input", "-i", required=True, 
                             help="Input CSV file path (format: package,version,registry)")
    batch_parser.add_argument("--output", "-o", default="vulnerability_report.csv", 
                             help="Output file path (default: vulnerability_report.csv)")
    batch_parser.add_argument("--format", "-f", choices=["json", "csv"], default="csv",
                             help="Output format (default: csv)")
    
    # Folder mode
    folder_parser = subparsers.add_parser("folder", help="Scan a code folder for dependencies")
    folder_parser.add_argument("--path", required=True, help="Path to the code folder")
    folder_parser.add_argument("--output", "-o", default="vulnerability_report.csv", 
                              help="Output file path (default: vulnerability_report.csv)")
    folder_parser.add_argument("--format", "-f", choices=["json", "csv"], default="csv",
                              help="Output format (default: csv)")
    
    # Parse arguments
    args = parser.parse_args()
    
    # Default output format
    output_format = args.format if hasattr(args, "format") else "json"
    output_file = args.output if hasattr(args, "output") else "vulnerability_report.json"
    
    # Set mode to single if not specified
    if not args.mode:
        parser.print_help()
        return
    
    print("SCA Scanner - Software Composition Analysis Tool")
    print("===============================================")
    
    results = []
    
    if args.mode == "single":
        print(f"Scanning package: {args.package} (version: {args.version or 'latest'}) from {args.registry}")
        results = check_packages([(args.package, args.version, args.registry.lower())])
        
    elif args.mode == "batch":
        print(f"Scanning packages from CSV file: {args.input}")
        try:
            batch_packages = []
            with open(args.input, "r", encoding="utf-8") as file:
                reader = csv.reader(file)
                header = next(reader, None)  # Skip header if exists
                
                if header and all(h.lower() in ["package", "version", "registry"] for h in header):
                    # CSV has header
                    pass
                else:
                    # No header or not recognized, rewind file
                    file.seek(0)
                    
                for row in reader:
                    if len(row) >= 3:
                        batch_packages.append((row[0].strip(), row[1].strip(), row[2].strip().lower()))
            
            print(f"Found {len(batch_packages)} packages in the CSV file")
            results = check_packages(batch_packages)
                
        except Exception as e:
            print(f"Error processing file: {str(e)}")
            return
            
    elif args.mode == "folder":
        print(f"Scanning code folder: {args.path}")
        results = scan_folder(args.path)
        
        if not results:
            print("No dependencies found or an error occurred during scanning.")
            return
    
    # Save results
    if results:
        if output_format == "json":
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=4)
        else:  # csv
            write_results_to_csv(results, output_file)
        
        print(f"Results saved to '{output_file}'")
        
        # Print summary
        vulnerabilities_count = sum(len(r.get("vulnerabilities", [])) for r in results)
        packages_with_vulns = sum(1 for r in results if r.get("vulnerabilities", []))
        
        print(f"\nSummary:")
        print(f"- Total packages scanned: {len(results)}")
        print(f"- Packages with vulnerabilities: {packages_with_vulns}")
        print(f"- Total vulnerabilities found: {vulnerabilities_count}")
        
        # Print top vulnerable packages
        if vulnerabilities_count > 0:
            print("\nTop vulnerable packages:")
            sorted_results = sorted(results, 
                                   key=lambda r: len(r.get("vulnerabilities", [])), 
                                   reverse=True)
            
            for i, r in enumerate(sorted_results[:5]):
                if r.get("vulnerabilities", []):
                    vuln_count = len(r.get("vulnerabilities", []))
                    print(f"  {i+1}. {r['package']} ({r['version']}): {vuln_count} vulnerabilities")

def read_csv(file_path):
    """Read package list from CSV file."""
    packages = []
    with open(file_path, "r", encoding="utf-8") as file:
        reader = csv.reader(file)
        next(reader, None)  # Skip header if present
        for row in reader:
            if len(row) >= 3:
                packages.append((row[0].strip(), row[1].strip(), row[2].strip().lower()))
    return packages

if __name__ == "__main__":
    main()