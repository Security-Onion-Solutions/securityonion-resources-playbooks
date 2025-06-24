#!/usr/bin/env python3
"""
Batch Template Processor - High Performance Version
Processes all playbooks from Claude's batch API output and expands template references
Optimized for processing 45k+ files with parallel processing and robust error handling
"""

import yaml
import sys
import argparse
from pathlib import Path
import shutil
from typing import Dict, List, Any, Optional, Tuple
import subprocess
from concurrent.futures import ProcessPoolExecutor, as_completed
import multiprocessing
import time
import traceback
from dataclasses import dataclass
import json

# Import the template engine from the same directory
sys.path.append(str(Path(__file__).parent))
from template_engine import ProductionTemplateEngine


@dataclass
class ProcessingResult:
    """Result of processing a single file"""
    file_path: str
    success: bool
    has_templates: bool
    template_count: int = 0
    error: Optional[str] = None
    error_traceback: Optional[str] = None
    processing_time: float = 0.0
    had_markdown_delimiters: bool = False


class BatchTemplateProcessor:
    def __init__(self, template_file: str = 'working_templates.yaml', num_workers: Optional[int] = None):
        """Initialize with template engine"""
        self.template_file = template_file
        self.num_workers = num_workers or multiprocessing.cpu_count()
        self.stats = {
            'processed': 0,
            'expanded': 0,
            'errors': 0,
            'templates_found': 0,
            'skipped': 0,
            'markdown_cleaned': 0
        }
        self.errors: List[ProcessingResult] = []
    
    def get_staged_files(self, input_dir: str = None) -> List[str]:
        """Get list of staged YAML files from git"""
        try:
            # Determine which directory to check for git repo
            check_dir = input_dir if input_dir else '.'
            
            # Try to find the git repository root from the input directory
            git_root_result = subprocess.run(
                ['git', 'rev-parse', '--show-toplevel'],
                capture_output=True,
                text=True,
                check=True,
                cwd=check_dir
            )
            git_root = git_root_result.stdout.strip()
            print(f"🔍 Git root: {git_root}")
            
            # Run git diff from the repository root
            result = subprocess.run(
                ['git', 'diff', '--cached', '--name-only', '--diff-filter=AM'],
                capture_output=True,
                text=True,
                check=True,
                cwd=git_root
            )
            
            print(f"🔍 Git diff output: '{result.stdout}'")
            
            # Filter for YAML files
            staged_files = []
            for file_path in result.stdout.strip().split('\n'):
                print(f"🔍 Processing git file: '{file_path}'")
                if file_path and (file_path.endswith('.yaml') or file_path.endswith('.yml')):
                    # Convert to absolute path from git root
                    abs_path = str(Path(git_root) / file_path)
                    staged_files.append(abs_path)
                    print(f"✅ Added YAML file: {abs_path}")
            
            return staged_files
            
        except subprocess.CalledProcessError as e:
            print(f"❌ Error getting staged files: {e}")
            return []
    
    def process_directory(self, input_dir: str, output_dir: str, staged_only: bool = False) -> Dict[str, int]:
        """Process all YAML files in input directory using parallel processing"""
        start_time = time.time()
        input_path = Path(input_dir)
        output_path = Path(output_dir)
        
        if not input_path.exists():
            raise FileNotFoundError(f"Input directory not found: {input_dir}")
        
        # Create output directory
        output_path.mkdir(parents=True, exist_ok=True)
        
        print(f"📁 Processing playbooks from: {input_dir}")
        print(f"📁 Output directory: {output_dir}")
        print(f"🚀 Using {self.num_workers} parallel workers")
        
        if staged_only:
            print("🔍 Processing only git staged files")
            staged_files = self.get_staged_files(input_dir)
            print(f"🔍 Found {len(staged_files)} staged YAML files")
            if staged_files:
                print(f"🔍 Staged files: {staged_files}")
            if not staged_files:
                print("⚠️  No staged YAML files found")
                return self.stats
            
            # Convert staged file paths to Path objects and filter by input directory
            yaml_files = []
            print(f"🔍 Input directory (resolved): {input_path.resolve()}")
            for staged_file in staged_files:
                file_path = Path(staged_file).resolve()
                print(f"🔍 Checking staged file: {file_path}")
                # Check if the staged file is in the input directory
                try:
                    relative_path = file_path.relative_to(input_path.resolve())
                    print(f"✅ File is in input directory: {relative_path}")
                    yaml_files.append(file_path)
                except ValueError:
                    print(f"❌ File is not in input directory, skipping")
                    continue
        else:
            # Find all YAML files
            yaml_files = list(input_path.glob("*.yaml")) + list(input_path.glob("*.yml"))
        
        if not yaml_files:
            print("⚠️  No YAML files found in input directory")
            return self.stats
        
        print(f"📊 Found {len(yaml_files)} playbook files to process")
        print(f"🚀 Starting parallel processing...", flush=True)
        
        # Process files in parallel
        with ProcessPoolExecutor(max_workers=self.num_workers) as executor:
            # Submit all tasks
            print(f"🔄 Submitting tasks to worker pool...", flush=True)
            future_to_file = {}
            for i, yaml_file in enumerate(yaml_files):
                future = executor.submit(process_file_worker, yaml_file, output_path, self.template_file)
                future_to_file[future] = yaml_file
                if (i + 1) % 1000 == 0:
                    print(f"📋 Submitted {i + 1}/{len(yaml_files)} tasks", flush=True)
            
            print(f"📋 Submitted all {len(future_to_file)} tasks to worker pool", flush=True)
            
            # Process results as they complete
            completed = 0
            print(f"🔄 Waiting for results from worker pool...", flush=True)
            for future in as_completed(future_to_file):
                completed += 1
                yaml_file = future_to_file[future]
                
                if completed == 1:
                    print(f"✅ First result received from worker", flush=True)
                
                try:
                    result: ProcessingResult = future.result(timeout=30)  # 30 second timeout per file
                    
                    # Update stats
                    self.stats['processed'] += 1
                    
                    if result.success:
                        if result.has_templates:
                            self.stats['expanded'] += 1
                            self.stats['templates_found'] += result.template_count
                        else:
                            self.stats['skipped'] += 1
                        if result.had_markdown_delimiters:
                            self.stats['markdown_cleaned'] += 1
                    else:
                        self.stats['errors'] += 1
                        self.errors.append(result)
                    
                    # Progress indicator
                    if completed % 50 == 0 or completed == len(yaml_files):
                        elapsed = time.time() - start_time
                        rate = completed / elapsed if elapsed > 0 else 0
                        eta = (len(yaml_files) - completed) / rate if rate > 0 else 0
                        print(f"⏳ Progress: {completed}/{len(yaml_files)} files "
                              f"({completed/len(yaml_files)*100:.1f}%) - "
                              f"Rate: {rate:.1f} files/sec - ETA: {eta:.1f}s", flush=True)
                
                except Exception as e:
                    print(f"❌ Unexpected error processing {yaml_file.name}: {e}", flush=True)
                    self.stats['errors'] += 1
                    self.errors.append(ProcessingResult(
                        file_path=str(yaml_file),
                        success=False,
                        has_templates=False,
                        error=str(e),
                        error_traceback=traceback.format_exc()
                    ))
        
        total_time = time.time() - start_time
        print(f"\n✅ Processing completed in {total_time:.2f} seconds")
        print(f"📈 Average: {len(yaml_files)/total_time:.1f} files/second")
        
        return self.stats
    
    def print_summary(self):
        """Print processing summary"""
        print("\n" + "="*50)
        print("📊 PROCESSING SUMMARY")
        print("="*50)
        print(f"Files processed:      {self.stats['processed']}")
        print(f"Files with templates: {self.stats['expanded']}")
        print(f"Files without templates: {self.stats['skipped']}")
        print(f"Total templates:      {self.stats['templates_found']}")
        print(f"Markdown cleaned:     {self.stats['markdown_cleaned']}")
        print(f"Errors:               {self.stats['errors']}")
        print("="*50)
        
        # Print error details if any
        if self.errors:
            print("\n" + "="*50)
            print("❌ ERROR SUMMARY")
            print("="*50)
            
            # Group errors by type
            error_types = {}
            for error in self.errors:
                # Extract the main error type
                error_msg = error.error
                if "yaml.scanner.ScannerError" in error_msg:
                    error_type = "YAML Scanner Error"
                    # Extract just the scanner error message
                    if "found character" in error_msg:
                        import re
                        match = re.search(r"found character.*?column \d+", error_msg)
                        if match:
                            error_msg = match.group()
                elif "yaml.parser.ParserError" in error_msg:
                    error_type = "YAML Parser Error"
                else:
                    error_type = "Other Error"
                
                if error_type not in error_types:
                    error_types[error_type] = []
                error_types[error_type].append((error.file_path, error_msg))
            
            # Print grouped errors
            for error_type, files in error_types.items():
                print(f"\n{error_type} ({len(files)} files):")
                if len(files) <= 5:
                    for file_path, msg in files:
                        print(f"  - {Path(file_path).name}: {msg}")
                else:
                    # Show first few examples
                    for file_path, msg in files[:3]:
                        print(f"  - {Path(file_path).name}: {msg}")
                    print(f"  ... and {len(files) - 3} more")
            
            print("\n" + "="*50)
            print("❌ FAILED FILES LIST")
            print("="*50)
            failed_files = [Path(e.file_path).name for e in self.errors]
            print(", ".join(sorted(failed_files)))
            print("="*50)
            
            # Save error report to file
            error_report_file = "template_processing_errors.json"
            with open(error_report_file, 'w') as f:
                error_data = [
                    {
                        'file': e.file_path,
                        'error': e.error,
                        'traceback': e.error_traceback
                    }
                    for e in self.errors
                ]
                json.dump(error_data, f, indent=2)
            print(f"\n📄 Detailed error report saved to: {error_report_file}")
            
            # Also save simple failed files list
            failed_files_file = "failed_files.txt"
            with open(failed_files_file, 'w') as f:
                for e in self.errors:
                    f.write(f"{e.file_path}\n")
            print(f"📄 Failed files list saved to: {failed_files_file}")


def clean_markdown_delimiters(content: str) -> Tuple[str, bool]:
    """Remove markdown code block delimiters from content"""
    lines = content.strip().split('\n')
    had_delimiters = False
    
    # Check for opening delimiter
    if lines and (lines[0].strip() == '```' or lines[0].strip() == '```yaml' or lines[0].strip() == '```yml'):
        lines.pop(0)
        had_delimiters = True
    
    # Check for closing delimiter
    if lines and lines[-1].strip() == '```':
        lines.pop()
        had_delimiters = True
    
    return '\n'.join(lines), had_delimiters


def process_file_worker(input_file: Path, output_dir: Path, template_file: str) -> ProcessingResult:
    """Worker function to process a single file - runs in separate process"""
    start_time = time.time()
    temp_file = None
    had_markdown_delimiters = False
    
    # Suppress verbose output from template engine in worker processes
    import os
    import io
    from contextlib import redirect_stdout, redirect_stderr
    
    # Debug: Log that worker started (only first few)
    import random
    if random.random() < 0.01:  # 1% chance to log
        print(f"🔧 Worker processing: {input_file.name}", flush=True)
    
    try:
        # Read the full content first
        with open(input_file, 'r') as f:
            content = f.read()
        
        # Clean markdown delimiters if present
        content, had_markdown_delimiters = clean_markdown_delimiters(content)
        
        # Quick check if file contains templates
        has_templates = 'template:' in content
        
        if not has_templates:
            # Just write the cleaned content
            output_file = output_dir / input_file.name
            with open(output_file, 'w') as f:
                f.write(content)
            return ProcessingResult(
                file_path=str(input_file),
                success=True,
                has_templates=False,
                processing_time=time.time() - start_time,
                had_markdown_delimiters=had_markdown_delimiters
            )
        
        # File has templates - process it
        # Suppress output during template engine operations
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            # Initialize template engine (each worker needs its own instance)
            engine = ProductionTemplateEngine(template_file)
        
        # Count templates
        template_count = content.count('template:')
        
        # Process through template engine
        temp_file = output_dir / f"temp_{input_file.name}"
        try:
            with open(temp_file, 'w') as f:
                f.write(content)
            
            # Process with template engine (suppress output)
            output_file = output_dir / input_file.name
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                engine.process_playbook_file(str(temp_file), str(output_file))
            
            return ProcessingResult(
                file_path=str(input_file),
                success=True,
                has_templates=True,
                template_count=template_count,
                processing_time=time.time() - start_time,
                had_markdown_delimiters=had_markdown_delimiters
            )
            
        finally:
            # Always clean up temp file
            if temp_file and temp_file.exists():
                temp_file.unlink()
    
    except Exception as e:
        # Clean up temp file on error
        if temp_file and temp_file.exists():
            try:
                temp_file.unlink()
            except:
                pass
        
        return ProcessingResult(
            file_path=str(input_file),
            success=False,
            has_templates=False,
            error=str(e),
            error_traceback=traceback.format_exc(),
            processing_time=time.time() - start_time,
            had_markdown_delimiters=had_markdown_delimiters
        )


def main():
    parser = argparse.ArgumentParser(
        description='Batch process playbooks to expand template references (high-performance version)'
    )
    parser.add_argument('--input-dir', '-i', required=True,
                       help='Directory containing templated playbooks')
    parser.add_argument('--output-dir', '-o', required=True,
                       help='Directory for expanded playbooks')
    parser.add_argument('--template-file', '-t', 
                       default='./templates/working_templates.yaml',
                       help='Template definition file')
    parser.add_argument('--staged', action='store_true',
                       help='Process only git staged files')
    parser.add_argument('--workers', '-w', type=int,
                       help='Number of parallel workers (default: CPU count)')
    
    args = parser.parse_args()
    
    try:
        processor = BatchTemplateProcessor(args.template_file, args.workers)
        stats = processor.process_directory(args.input_dir, args.output_dir, args.staged)
        processor.print_summary()
        
        # Exit with error if any files failed
        return 1 if stats['errors'] > 0 else 0
        
    except Exception as e:
        print(f"❌ Fatal error: {e}")
        return 1


if __name__ == '__main__':
    sys.exit(main())