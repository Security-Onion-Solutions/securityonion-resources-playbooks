#!/usr/bin/env python3
"""
Playbook Validation Script
Validates expanded playbooks for correct metadata and Sigma query syntax
"""

import yaml
import sys
import argparse
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Any, Tuple, Optional
import re
from datetime import datetime
from multiprocessing import Pool, cpu_count
from functools import partial
import time
import threading
import shutil
import os
import hashlib

# Custom YAML representer to preserve block scalars for queries
def represent_literal_str(dumper, data):
    if '\n' in data:
        return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|')
    return dumper.represent_scalar('tag:yaml.org,2002:str', data)

class LiteralStr(str):
    pass

yaml.add_representer(LiteralStr, represent_literal_str)


class QueryCache:
    """Cache for Sigma query validation results to avoid duplicate validation"""
    def __init__(self):
        self.cache = {}  # hash -> (is_valid, error_msg)
        self.hits = 0
        self.misses = 0
    
    def get_query_hash(self, query_dict: Dict) -> str:
        """Generate consistent hash for query dictionary"""
        # Normalize query for consistent hashing
        normalized = yaml.dump(query_dict, sort_keys=True, default_flow_style=False)
        return hashlib.sha256(normalized.encode()).hexdigest()
    
    def get_stats(self) -> Dict[str, int]:
        """Get cache statistics"""
        total = self.hits + self.misses
        hit_rate = (self.hits / total * 100) if total > 0 else 0
        return {
            'hits': self.hits,
            'misses': self.misses,
            'total': total,
            'hit_rate': hit_rate,
            'unique_queries': len(self.cache)
        }


def handle_failed_playbook(file_path: Path, playbook: Optional[Dict], reset_dir: str, validation_dir: Optional[str]):
    """Handle failed playbook by deleting from validation and reset dirs, and creating backup"""
    try:
        # Extract SID from playbook or filename
        sid = None
        if playbook and 'id' in playbook:
            sid = str(playbook['id'])
        else:
            # Try to extract from filename (e.g., playbook-2027695.yaml -> 2027695)
            import re
            match = re.search(r'(\d+)', file_path.name)
            if match:
                sid = match.group(1)
            else:
                sid = file_path.stem  # Use filename without extension as fallback
        
        # Generate timestamp
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        
        # Create backup filename
        backup_filename = f"{sid}-{timestamp}.yaml"
        
        # Create failed directory in current working directory
        failed_dir = Path("./failed")
        failed_dir.mkdir(exist_ok=True)
        backup_path = failed_dir / backup_filename
        
        # Copy original file to backup location
        if file_path.exists():
            shutil.copy2(file_path, backup_path)
            print(f"  📁 Backed up to: {backup_path}")
        
        # Delete from validation directory (original location)
        if file_path.exists():
            file_path.unlink()
            print(f"  🗑️  Deleted from validation dir: {file_path}")
        
        # Delete from reset directory if it exists
        reset_path = Path(reset_dir) / file_path.name
        if reset_path.exists():
            reset_path.unlink()
            print(f"  🗑️  Deleted from reset dir: {reset_path}")
        
    except Exception as e:
        print(f"  ❌ Error handling failed playbook {file_path.name}: {e}")


class ProgressBar:
    """Simple progress bar for command line"""
    def __init__(self, total: int, width: int = 50):
        self.total = total
        self.width = width
        self.current = 0
        self.lock = threading.Lock()
        
    def update(self, increment: int = 1):
        with self.lock:
            self.current += increment
            self._display()
    
    def _display(self):
        if self.total == 0:
            return
            
        progress = self.current / self.total
        filled = int(self.width * progress)
        bar = '█' * filled + '░' * (self.width - filled)
        percent = int(progress * 100)
        
        print(f'\r🔍 Progress: [{bar}] {percent}% ({self.current}/{self.total})', end='', flush=True)
        
        if self.current >= self.total:
            print()  # New line when complete


def validate_single_playbook(file_path: Path, fixup: bool = False, reset_dir: Optional[str] = None, validation_dir: Optional[str] = None, query_cache: Optional[QueryCache] = None) -> Dict[str, Any]:
    """Static function to validate a single playbook for multiprocessing"""
    validator = PlaybookValidator()
    validator.fixup = fixup  # Set fixup on the validator instance
    file_errors = []
    
    # Create a per-worker query cache if not provided
    if query_cache is None:
        query_cache = QueryCache()
    
    try:
        with open(file_path, 'r') as f:
            playbook = yaml.safe_load(f)
        
        if not playbook:
            file_errors.append("Empty or invalid YAML file")
            result = {
                'file': file_path.name,
                'success': False,
                'errors': file_errors,
                'stats': {'total': 1, 'passed': 0, 'failed': 1, 'metadata_errors': 1, 'query_errors': 0, 'template_found': 0},
                'playbook_id': None,
                'file_path': file_path
            }
            
            # Handle reset logic if reset is enabled
            if reset_dir:
                handle_failed_playbook(file_path, None, reset_dir, validation_dir)
            
            return result
        
        # Validate metadata
        metadata_valid = validator.validate_metadata(playbook, file_path.name, file_errors)
        
        # Validate questions and queries
        validation_result = validator.validate_questions_with_fixup(playbook, file_path.name, file_errors, fixup, query_cache)
        
        # Check if we need to write back any fixes (metadata or queries)
        file_modified = False
        
        if isinstance(validation_result, dict) and validation_result.get('fixed'):
            # Queries were fixed
            file_modified = True
            
        # Check if metadata was fixed (look for fix messages in file_errors)
        metadata_fixed = any("✅ FIXED:" in error for error in file_errors)
        if metadata_fixed:
            file_modified = True
        
        if file_modified and fixup:
            # Write back to file with fixes
            success = True
            try:
                with open(file_path, 'w') as f:
                    # Define custom representer for literal blocks
                    def literal_str_representer(dumper, data):
                        if '\n' in data:
                            return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|')
                        return dumper.represent_scalar('tag:yaml.org,2002:str', data)
                    
                    # Use SafeDumper with custom string handling
                    yaml.add_representer(str, literal_str_representer, Dumper=yaml.SafeDumper)
                    yaml.add_representer(LiteralStr, represent_literal_str, Dumper=yaml.SafeDumper)
                    
                    # Use the fixed playbook from validation_result if available, otherwise use the modified playbook
                    playbook_to_write = validation_result['playbook'] if isinstance(validation_result, dict) and validation_result.get('fixed') else playbook
                    yaml.dump(playbook_to_write, f, Dumper=yaml.SafeDumper, default_flow_style=False, sort_keys=False, allow_unicode=True, width=1000)
                file_errors.append(f"✅ File updated with fixes")
            except Exception as e:
                file_errors.append(f"❌ Failed to write fixes to file: {e}")
                success = False
        else:
            success = metadata_valid and validation_result
        stats = {
            'total': 1,
            'passed': 1 if success else 0,
            'failed': 0 if success else 1,
            'metadata_errors': validator.stats['metadata_errors'],
            'query_errors': validator.stats['query_errors'],
            'template_found': validator.stats['template_found']
        }
        
        result = {
            'file': file_path.name,
            'success': success,
            'errors': file_errors,
            'stats': stats,
            'playbook_id': playbook.get('id') if playbook else None,
            'file_path': file_path
        }
        
        # Handle reset logic if playbook failed and reset is enabled
        if not success and reset_dir:
            handle_failed_playbook(file_path, playbook, reset_dir, validation_dir)
        
        return result
        
    except yaml.YAMLError as e:
        file_errors.append(f"YAML parsing error: {e}")
        result = {
            'file': file_path.name,
            'success': False,
            'errors': file_errors,
            'stats': {'total': 1, 'passed': 0, 'failed': 1, 'metadata_errors': 0, 'query_errors': 1, 'template_found': 0},
            'playbook_id': None,
            'file_path': file_path
        }
        
        # Handle reset logic if reset is enabled
        if reset_dir:
            handle_failed_playbook(file_path, None, reset_dir, validation_dir)
        
        return result
        
    except Exception as e:
        file_errors.append(f"Unexpected error: {e}")
        result = {
            'file': file_path.name,
            'success': False,
            'errors': file_errors,
            'stats': {'total': 1, 'passed': 0, 'failed': 1, 'metadata_errors': 0, 'query_errors': 1, 'template_found': 0},
            'playbook_id': None,
            'file_path': file_path
        }
        
        # Handle reset logic if reset is enabled
        if reset_dir:
            handle_failed_playbook(file_path, None, reset_dir, validation_dir)
        
        return result


class PlaybookValidator:
    def __init__(self):
        self.errors = []
        self.warnings = []
        self.stats = {
            'total': 0,
            'passed': 0,
            'failed': 0,
            'metadata_errors': 0,
            'query_errors': 0,
            'template_found': 0,
            'duplicate_ids': 0
        }
    
    def get_staged_yaml_files(self, directory: Path) -> List[Path]:
        """Get list of staged YAML files in the given directory"""
        try:
            # Get the repository root
            git_root_result = subprocess.run(
                ['git', 'rev-parse', '--show-toplevel'],
                capture_output=True,
                text=True,
                cwd=directory
            )
            
            if git_root_result.returncode != 0:
                print(f"❌ Error: Not in a git repository")
                return []
            
            git_root = Path(git_root_result.stdout.strip())
            
            # Get list of staged files
            result = subprocess.run(
                ['git', 'diff', '--cached', '--name-only', '--diff-filter=ACM'],
                capture_output=True,
                text=True,
                cwd=git_root
            )
            
            if result.returncode != 0:
                print(f"❌ Error getting staged files: {result.stderr}")
                return []
            
            # Get relative path from git root to target directory
            try:
                rel_dir = directory.relative_to(git_root)
            except ValueError:
                # Directory is not under git root
                rel_dir = directory
            
            # Filter for YAML files in the specified directory
            staged_files = []
            for file in result.stdout.strip().split('\n'):
                if file:  # Skip empty lines
                    file_path = git_root / file
                    # Check if file is a YAML file and is in our target directory
                    if file_path.suffix in ['.yaml', '.yml'] and file_path.exists():
                        # Check if the file is in the target directory
                        try:
                            file_path.relative_to(directory)
                            staged_files.append(file_path)
                        except ValueError:
                            # File is not in the target directory
                            pass
            
            return staged_files
            
        except Exception as e:
            print(f"❌ Error getting staged files: {e}")
            return []
    
    def validate_directory(self, directory: str, workers: Optional[int] = None, fixup: bool = False, reset_dir: Optional[str] = None, staged_only: bool = False) -> Tuple[int, int]:
        """Validate all YAML playbooks in directory or only staged files"""
        self.fixup = fixup  # Store fixup setting on instance
        dir_path = Path(directory).resolve()  # Convert to absolute path
        
        if not dir_path.exists():
            print(f"❌ Error: Directory not found: {directory}")
            return 0, 1
        
        # Find YAML files based on whether we're validating staged files only
        if staged_only:
            yaml_files = self.get_staged_yaml_files(dir_path)
        else:
            # Find all YAML files recursively
            yaml_files = list(dir_path.rglob("*.yaml")) + list(dir_path.rglob("*.yml"))
        
        if not yaml_files:
            if staged_only:
                print(f"⚠️  No staged YAML files found in {directory}")
            else:
                print(f"⚠️  No YAML files found in {directory}")
            return 0, 0
        
        if staged_only:
            print(f"\n🔍 Validating {len(yaml_files)} staged playbooks in {directory}")
        else:
            print(f"\n🔍 Validating {len(yaml_files)} playbooks in {directory} (recursive)")
        
        # Create query cache for performance optimization
        query_cache = QueryCache()
        
        # Parallel processing with per-worker caches
        if workers is None:
            workers = min(cpu_count(), 8)  # Cap at 8 workers
        print(f"Using {workers} parallel workers\n")
        
        start_time = time.time()
        
        # Initialize progress bar
        progress_bar = ProgressBar(len(yaml_files))
        failed_files = []
        all_results = []
        
        # Process files in parallel - each worker gets its own query cache
        with Pool(workers) as pool:
            validate_func = partial(validate_single_playbook, fixup=fixup, reset_dir=reset_dir, validation_dir=directory, query_cache=None)
            for result in pool.imap_unordered(validate_func, sorted(yaml_files)):
                progress_bar.update(1)
                all_results.append(result)
                if result['success']:
                    self.stats['passed'] += 1
                else:
                    self.stats['failed'] += 1
                    failed_files.append(result)
                
                # Aggregate error counts
                self.stats['metadata_errors'] += result['stats']['metadata_errors']
                self.stats['query_errors'] += result['stats']['query_errors']
                self.stats['template_found'] += result['stats']['template_found']
        
        self.stats['total'] = len(yaml_files)
        
        # Print errors for failed files after progress bar completes
        print()  # Extra newline after progress bar
        for result in failed_files:
            print(f"📄 Failed: {result['file']}")
            for error in result['errors']:
                print(f"  ❌ {error}")
        
        elapsed = time.time() - start_time
        print(f"\n⏱️  Validation completed in {elapsed:.2f} seconds")
        
        # Check for duplicate IDs
        self.check_duplicate_ids(all_results)
        
        self.print_summary()
        return self.stats['passed'], self.stats['failed']
    
    def validate_playbook(self, file_path: Path, reset_dir: Optional[str] = None, validation_dir: Optional[str] = None, query_cache: Optional[QueryCache] = None) -> bool:
        """Validate a single playbook file"""
        self.stats['total'] += 1
        print(f"📄 Validating: {file_path.name}")
        
        try:
            with open(file_path, 'r') as f:
                playbook = yaml.safe_load(f)
            
            if not playbook:
                self.log_error(file_path.name, "Empty or invalid YAML file")
                self.stats['failed'] += 1
                return False
            
            # Track errors for this file
            file_errors = []
            
            # Validate metadata
            metadata_valid = self.validate_metadata(playbook, file_path.name, file_errors)
            
            # Validate questions and queries
            queries_valid = self.validate_questions(playbook, file_path.name, file_errors, query_cache)
            
            if not metadata_valid or not queries_valid:
                self.stats['failed'] += 1
                for error in file_errors:
                    print(f"  ❌ {error}")
                
                # Handle reset logic if playbook failed and reset is enabled
                if reset_dir:
                    handle_failed_playbook(file_path, playbook, reset_dir, validation_dir)
                
                return False
            
            print(f"  ✅ Passed all validations")
            self.stats['passed'] += 1
            return True
            
        except yaml.YAMLError as e:
            self.log_error(file_path.name, f"YAML parsing error: {e}")
            self.stats['failed'] += 1
            
            # Handle reset logic if reset is enabled
            if reset_dir:
                handle_failed_playbook(file_path, None, reset_dir, validation_dir)
            
            return False
        except Exception as e:
            self.log_error(file_path.name, f"Unexpected error: {e}")
            self.stats['failed'] += 1
            
            # Handle reset logic if reset is enabled
            if reset_dir:
                handle_failed_playbook(file_path, None, reset_dir, validation_dir)
            
            return False
    
    def validate_metadata(self, playbook: Dict, filename: str, file_errors: List[str]) -> bool:
        """Validate playbook metadata against requirements"""
        required_fields = {
            'name': str,
            'id': int,
            'description': str,
            'type': str,
            'detection_id': int,
            'detection_category': str,
            'detection_type': str,
            'contributors': list,
            'created': (str, type(datetime.now().date())),  # Accept both str and date objects
            'questions': list
        }
        
        valid = True
        
        # Check required fields
        for field, expected_type in required_fields.items():
            if field not in playbook:
                file_errors.append(f"Missing required field: {field}")
                self.stats['metadata_errors'] += 1
                valid = False
            elif isinstance(expected_type, tuple):
                # Handle multiple allowed types
                if not any(isinstance(playbook[field], t) for t in expected_type):
                    type_names = " or ".join(t.__name__ for t in expected_type)
                    file_errors.append(f"Invalid type for {field}: expected {type_names}, got {type(playbook[field]).__name__}")
                    self.stats['metadata_errors'] += 1
                    valid = False
            elif not isinstance(playbook[field], expected_type):
                file_errors.append(f"Invalid type for {field}: expected {expected_type.__name__}, got {type(playbook[field]).__name__}")
                self.stats['metadata_errors'] += 1
                valid = False
        
        # Check detection_id and detection_category relationship
        if 'detection_id' in playbook and 'detection_category' in playbook:
            # If detection_id is not empty (non-zero), detection_category should be empty
            if playbook['detection_id'] != 0 and playbook['detection_category'] != "":
                if getattr(self, 'fixup', False):
                    # Fix by setting detection_category to empty string
                    playbook['detection_category'] = ""
                    file_errors.append("✅ FIXED: Set detection_category to empty string since detection_id is not empty")
                else:
                    file_errors.append(f"If detection_id is not empty ({playbook['detection_id']}), detection_category should be empty, got '{playbook['detection_category']}'")
                    valid = False
        
        # Specific validations
        if 'name' in playbook:
            if 'ET' not in playbook['name'] and 'GPL' not in playbook['name']:
                file_errors.append("Name should include ET or GPL category (e.g., 'ET MALWARE', 'ET EXPLOIT')")
                valid = False
        
        if 'id' in playbook:
            playbook_id = playbook['id']
            if not (1200001 <= playbook_id <= 1999999):
                file_errors.append(f"ID should be between 1200001 and 1999999, got {playbook_id}")
                valid = False
        
        if 'type' in playbook and playbook['type'] != 'detection':
            file_errors.append(f"Type should be 'detection', got '{playbook['type']}'")
            valid = False
        
        if 'detection_type' in playbook and playbook['detection_type'] != 'nids':
            file_errors.append(f"Detection type should be 'nids', got '{playbook['detection_type']}'")
            valid = False
        
        if 'contributors' in playbook:
            if not isinstance(playbook['contributors'], list) or 'SecurityOnionSolutions' not in playbook['contributors']:
                file_errors.append("Contributors should include 'SecurityOnionSolutions'")
                valid = False
        
        if 'created' in playbook:
            # Handle both string dates and datetime objects from YAML parser
            if isinstance(playbook['created'], str):
                try:
                    datetime.strptime(playbook['created'], '%Y-%m-%d')
                except ValueError:
                    file_errors.append(f"Created date should be YYYY-MM-DD format, got '{playbook['created']}'")
                    valid = False
            elif hasattr(playbook['created'], 'strftime'):
                # It's already a date/datetime object, which is valid
                pass
            else:
                file_errors.append(f"Created date has invalid type: {type(playbook['created']).__name__}")
                valid = False
        
        if 'questions' in playbook:
            num_questions = len(playbook['questions'])
            if num_questions < 8 or num_questions > 15:
                file_errors.append(f"Should have 8-14 questions, found {num_questions}")
                valid = False
        
        return valid
    
    def validate_questions(self, playbook: Dict, filename: str, file_errors: List[str], query_cache: Optional[QueryCache] = None) -> bool:
        """Validate questions and their queries"""
        if 'questions' not in playbook:
            return True  # Already caught in metadata validation
        
        valid = True
        
        # First, do basic validation and collect queries for batch validation
        queries_to_validate = []
        structural_errors = False
        
        for i, question in enumerate(playbook['questions'], 1):
            # Validate question structure
            required_q_fields = ['question', 'context', 'range', 'query']
            
            has_structural_error = False
            for field in required_q_fields:
                if field not in question:
                    file_errors.append(f"Question {i}: Missing required field '{field}'")
                    valid = False
                    has_structural_error = True
                    structural_errors = True
            
            if has_structural_error:
                continue
                
            # Check for template references (shouldn't exist in expanded playbooks)
            if 'query' in question and isinstance(question['query'], dict):
                if 'template' in question['query']:
                    file_errors.append(f"Question {i}: Found unexpanded template reference '{question['query']['template']}'")
                    self.stats['template_found'] += 1
                    valid = False
                    structural_errors = True
                    continue
            
            # Collect query for batch validation if it exists
            if 'query' in question:
                queries_to_validate.append((question['query'], i, question))
        
        # Try batch validation first (only if no structural errors)
        batch_success = False
        if queries_to_validate and not structural_errors:
            batch_success = self.validate_sigma_queries_batch(queries_to_validate, filename, file_errors)
            
        if batch_success:
            # All queries passed batch validation
            return valid
        else:
            # Batch validation failed or we had structural errors - validate individually
            # This allows us to identify which specific queries failed
            for i, question in enumerate(playbook['questions'], 1):
                # Skip questions with missing fields
                required_q_fields = ['question', 'context', 'range', 'query']
                if not all(field in question for field in required_q_fields):
                    continue
                    
                # Skip template references
                if 'query' in question and isinstance(question['query'], dict):
                    if 'template' in question['query']:
                        continue
                
                # Validate Sigma query individually
                if 'query' in question:
                    query_valid = self.validate_sigma_query(question['query'], i, filename, file_errors, question, getattr(self, 'fixup', False), query_cache)
                    if not query_valid:
                        valid = False
        
        return valid
    
    def validate_questions_with_fixup(self, playbook: Dict, filename: str, file_errors: List[str], fixup: bool = False, query_cache: Optional[QueryCache] = None):
        """Validate questions and optionally fix them, returning fixed playbook if changes made"""
        if 'questions' not in playbook:
            return True  # Already caught in metadata validation
        
        valid = True
        playbook_modified = False
        
        # First, do basic validation and collect queries for batch validation
        queries_to_validate = []
        structural_errors = False
        
        for i, question in enumerate(playbook['questions'], 1):
            # Validate question structure
            required_q_fields = ['question', 'context', 'range', 'query']
            
            has_structural_error = False
            for field in required_q_fields:
                if field not in question:
                    file_errors.append(f"Question {i}: Missing required field '{field}'")
                    valid = False
                    has_structural_error = True
                    structural_errors = True
            
            if has_structural_error:
                continue
                
            # Check for template references (shouldn't exist in expanded playbooks)
            if 'query' in question and isinstance(question['query'], dict):
                if 'template' in question['query']:
                    file_errors.append(f"Question {i}: Found unexpanded template reference '{question['query']['template']}'")
                    self.stats['template_found'] += 1
                    valid = False
                    structural_errors = True
                    continue
            
            # Collect query for batch validation if it exists
            if 'query' in question:
                queries_to_validate.append((question['query'], i, question))
        
        # Try batch validation first (only if no structural errors)
        batch_success = False
        if queries_to_validate and not structural_errors:
            batch_success = self.validate_sigma_queries_batch(queries_to_validate, filename, file_errors)
            
        if batch_success:
            # All queries passed batch validation
            return valid
        else:
            # Batch validation failed or we had structural errors - validate individually
            # This allows us to identify which specific queries failed
            for i, question in enumerate(playbook['questions'], 1):
                # Skip questions with missing fields
                required_q_fields = ['question', 'context', 'range', 'query']
                if not all(field in question for field in required_q_fields):
                    continue
                    
                # Skip template references
                if 'query' in question and isinstance(question['query'], dict):
                    if 'template' in question['query']:
                        continue
                
                # Validate Sigma query individually
                if 'query' in question:
                    query_result = self.validate_sigma_query(question['query'], i, filename, file_errors, question, fixup, query_cache)
                    if isinstance(query_result, dict) and query_result.get('fixed'):
                        # Update the question with the fixed query - use LiteralStr to preserve block format
                        fixed_yaml = yaml.dump(query_result['fixed_query'], default_flow_style=False, width=1000).strip()
                        question['query'] = LiteralStr(fixed_yaml)
                        playbook_modified = True
                        file_errors.append(f"Question {i}: ✅ FIXED and updated in playbook")
                    elif not query_result:
                        valid = False
        
        if playbook_modified and fixup:
            return {"fixed": True, "playbook": playbook}
        else:
            return valid
    
    def fix_sigma_query_structure(self, query_dict: Dict) -> Dict:
        """Fix common Sigma query structure issues"""
        import copy
        import json
        fixed_query = copy.deepcopy(query_dict)
        
        # Fix misplaced condition field
        if 'condition' in fixed_query and 'detection' in fixed_query:
            # Move condition inside detection block if it's at root level
            if 'condition' not in fixed_query['detection']:
                fixed_query['detection']['condition'] = fixed_query['condition']
                del fixed_query['condition']
        
        # Fix missing condition field - simple case only
        if 'detection' in fixed_query and isinstance(fixed_query['detection'], dict):
            detection = fixed_query['detection']
            # Only add condition if missing and we have exactly one selection block
            if 'condition' not in detection:
                selection_keys = [key for key in detection.keys() if key.startswith('selection') or key == 'selection']
                if len(selection_keys) == 1 and selection_keys[0] == 'selection':
                    # Simple case: only 'selection' exists, add 'condition: selection'
                    detection['condition'] = 'selection'
        
        # Fix incorrect |regex: modifier to |re: by recursively updating dict keys
        def fix_regex_keys(obj):
            if isinstance(obj, dict):
                new_dict = {}
                for key, value in obj.items():
                    # Fix the key if it contains |regex (note: no colon, that's YAML syntax)
                    new_key = key.replace('|regex', '|re') if isinstance(key, str) and '|regex' in key else key
                    # Recursively fix the value
                    new_value = fix_regex_keys(value)
                    new_dict[new_key] = new_value
                return new_dict
            elif isinstance(obj, list):
                return [fix_regex_keys(item) for item in obj]
            else:
                return obj
        
        # Apply the fix
        fixed_query = fix_regex_keys(fixed_query)
        
        return fixed_query
    
    def validate_sigma_queries_batch(self, queries: List[Tuple[Any, int, Dict]], filename: str, file_errors: List[str]) -> bool:
        """Validate multiple Sigma queries in a single batch for performance"""
        if not queries:
            return True
            
        # Create a temp file with all queries as separate Sigma rules
        sigma_rules = []
        query_map = {}  # Map rule index to question number
        
        for idx, (query, question_num, question_obj) in enumerate(queries):
            # Parse query if it's a string
            if isinstance(query, str):
                try:
                    query_dict = yaml.safe_load(query)
                except yaml.YAMLError:
                    # Skip invalid YAML queries in batch
                    continue
            else:
                query_dict = query
                
            # Skip template queries
            if isinstance(query_dict, dict) and 'template' in query_dict:
                continue
                
            # Validate basic structure
            if not isinstance(query_dict, dict) or 'logsource' not in query_dict or 'detection' not in query_dict:
                continue
                
            # Create a Sigma rule
            sigma_rule = {
                'title': f'Batch validation test for {filename} Q{question_num}',
                'logsource': query_dict['logsource'],
                'detection': query_dict['detection']
            }
            
            # Add optional fields
            if 'aggregation' in query_dict:
                sigma_rule['aggregation'] = query_dict['aggregation']
            if 'fields' in query_dict:
                sigma_rule['fields'] = query_dict['fields']
                
            sigma_rules.append(sigma_rule)
            query_map[len(sigma_rules) - 1] = (question_num, question_obj)
        
        if not sigma_rules:
            # No valid queries to batch validate
            return True
            
        try:
            # Write all rules to a single temp file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as tmp:
                # Write multiple documents in YAML format
                for i, rule in enumerate(sigma_rules):
                    if i > 0:
                        tmp.write('---\n')  # YAML document separator
                    yaml.dump(rule, tmp)
                tmp_path = tmp.name
                
            # Run sigma convert on the batch
            script_dir = Path(__file__).parent
            pipeline_path = script_dir / 'validation_pipeline.yaml'
            result = subprocess.run(
                ['sigma', 'convert', '-p', str(pipeline_path), '-t', 'security_onion', tmp_path],
                capture_output=True,
                text=True
            )
            
            # Clean up temp file
            Path(tmp_path).unlink()
            
            return result.returncode == 0
            
        except Exception as e:
            # Batch validation failed due to system error
            return False

    def validate_sigma_query(self, query: Any, question_num: int, filename: str, file_errors: List[str], question_obj: Dict = None, fixup: bool = False, query_cache: Optional[QueryCache] = None) -> bool:
        """Validate a Sigma query using sigma convert"""
        # Get question text preview if available
        question_preview = ""
        if question_obj and 'question' in question_obj:
            q_text = question_obj['question'].replace('\n', ' ').strip()
            question_preview = f" '{q_text[:30]}...'" if len(q_text) > 30 else f" '{q_text}'"
        
        if isinstance(query, dict) and 'template' in query:
            # Should have been caught earlier, but double-check
            return False
        
        # Parse the query string if it's a string
        if isinstance(query, str):
            try:
                query_dict = yaml.safe_load(query)
            except yaml.YAMLError:
                file_errors.append(f"Question {question_num}{question_preview}: Invalid YAML in query")
                self.stats['query_errors'] += 1
                return False
        else:
            query_dict = query
        
        # Check cache first if available
        if query_cache:
            query_hash = query_cache.get_query_hash(query_dict)
            if query_hash in query_cache.cache:
                query_cache.hits += 1
                is_valid, cached_error = query_cache.cache[query_hash]
                if not is_valid:
                    file_errors.append(f"Question {question_num}{question_preview}: {cached_error}")
                    self.stats['query_errors'] += 1
                return is_valid
            else:
                query_cache.misses += 1
        
        # Log the query being validated for debugging
        query_preview = str(query_dict).replace('\n', ' ')[:100] + '...' if len(str(query_dict)) > 100 else str(query_dict)
        
        # Validate query has required Sigma fields
        if not isinstance(query_dict, dict):
            file_errors.append(f"Question {question_num}{question_preview}: Query should be a dictionary")
            self.stats['query_errors'] += 1
            return False
        
        required_sigma_fields = ['logsource', 'detection']
        for field in required_sigma_fields:
            if field not in query_dict:
                file_errors.append(f"Question {question_num}{question_preview}: Missing required Sigma field '{field}'")
                self.stats['query_errors'] += 1
                return False
        
        # Create a minimal Sigma rule for validation
        sigma_rule = {
            'title': f'Validation test for {filename} Q{question_num}',
            'logsource': query_dict['logsource'],
            'detection': query_dict['detection']
        }
        
        # Add optional fields if present
        if 'aggregation' in query_dict:
            sigma_rule['aggregation'] = query_dict['aggregation']
        if 'fields' in query_dict:
            sigma_rule['fields'] = query_dict['fields']
        
        # Write to temp file and validate with sigma
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as tmp:
                yaml.dump(sigma_rule, tmp)
                tmp_path = tmp.name
            
            # Run sigma convert
            script_dir = Path(__file__).parent
            pipeline_path = script_dir / 'validation_pipeline.yaml'
            result = subprocess.run(
                ['sigma', 'convert', '-p', str(pipeline_path), '-t', 'security_onion', tmp_path],
                capture_output=True,
                text=True
            )
            
            # Clean up temp file
            Path(tmp_path).unlink()
            
            if result.returncode != 0:
                error_msg = result.stderr.strip() if result.stderr else "Unknown error"
                # Extract just the final error message from the traceback
                error_lines = error_msg.split('\n')
                for line in reversed(error_lines):
                    if line.strip() and not line.startswith(' '):
                        error_msg = line.strip()
                        break
                
                # Try to fix common structural issues if fixup is enabled
                if fixup:
                    try:
                        fixed_query_dict = self.fix_sigma_query_structure(query_dict.copy())
                        # Only retry if we actually made changes
                        if fixed_query_dict != query_dict:
                            # Create a new temp file with the fixed query
                            fixed_sigma_rule = {
                                'title': f'Validation test for {filename} Q{question_num} (fixed)',
                                'logsource': fixed_query_dict['logsource'],
                                'detection': fixed_query_dict['detection']
                            }
                            
                            # Add optional fields if present
                            if 'aggregation' in fixed_query_dict:
                                fixed_sigma_rule['aggregation'] = fixed_query_dict['aggregation']
                            if 'fields' in fixed_query_dict:
                                fixed_sigma_rule['fields'] = fixed_query_dict['fields']
                            
                            with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as tmp_fixed:
                                yaml.dump(fixed_sigma_rule, tmp_fixed)
                                tmp_fixed_path = tmp_fixed.name
                            
                            # Test the fixed query
                            fixed_result = subprocess.run(
                                ['sigma', 'convert', '-p', str(pipeline_path), '-t', 'security_onion', tmp_fixed_path],
                                capture_output=True,
                                text=True
                            )
                            
                            # Clean up temp file
                            Path(tmp_fixed_path).unlink()
                            
                            if fixed_result.returncode == 0:
                                file_errors.append(f"Question {question_num}{question_preview}: ✅ FIXED - Sigma query structure was corrected")
                                # Cache the successful fix
                                if query_cache:
                                    query_cache.cache[query_cache.get_query_hash(fixed_query_dict)] = (True, None)
                                # Return the fixed query so it can be written back to the file
                                return {"fixed": True, "fixed_query": fixed_query_dict}
                            else:
                                # Fixed query still fails, continue with original error
                                pass
                    except Exception as fix_error:
                        # If fixing fails, continue with original error
                        pass
                
                # Include query preview in error message for debugging
                full_error_msg = f"Sigma validation failed for query: {query_preview} - Error: {error_msg}"
                file_errors.append(f"Question {question_num}{question_preview}: {full_error_msg}")
                self.stats['query_errors'] += 1
                
                # Cache the failure
                if query_cache:
                    query_cache.cache[query_cache.get_query_hash(query_dict)] = (False, full_error_msg)
                
                return False
            
            # Success - cache the result
            if query_cache:
                query_cache.cache[query_cache.get_query_hash(query_dict)] = (True, None)
            
            return True
            
        except FileNotFoundError:
            file_errors.append("Sigma command not found - please install sigma-cli")
            return False
        except Exception as e:
            file_errors.append(f"Question {question_num}{question_preview}: Error running sigma validation - {e}")
            self.stats['query_errors'] += 1
            return False
    
    def check_duplicate_ids(self, results: List[Dict]) -> None:
        """Check for duplicate playbook IDs across all results"""
        id_to_files = {}
        
        # Collect all IDs and their associated files
        for result in results:
            playbook_id = result.get('playbook_id')
            if playbook_id is not None:
                if playbook_id not in id_to_files:
                    id_to_files[playbook_id] = []
                id_to_files[playbook_id].append(result['file'])
        
        # Check for duplicates
        duplicate_found = False
        for playbook_id, files in id_to_files.items():
            if len(files) > 1:
                duplicate_found = True
                print(f"❌ Duplicate ID {playbook_id} found in files: {', '.join(files)}")
                self.stats['duplicate_ids'] += 1
                self.stats['failed'] += len(files) - 1  # Count extra occurrences as failures
                self.stats['passed'] -= len(files) - 1   # Reduce passed count
        
        if duplicate_found:
            print()  # Extra newline after duplicate warnings
    
    def log_error(self, filename: str, error: str):
        """Log an error"""
        self.errors.append(f"{filename}: {error}")
        print(f"  ❌ {error}")
    
    def print_summary(self):
        """Print validation summary"""
        print("\n" + "="*60)
        print("📊 VALIDATION SUMMARY")
        print("="*60)
        print(f"Total playbooks:      {self.stats['total']}")
        print(f"✅ Passed:           {self.stats['passed']}")
        print(f"❌ Failed:           {self.stats['failed']}")
        print(f"Metadata errors:      {self.stats['metadata_errors']}")
        print(f"Query errors:         {self.stats['query_errors']}")
        print(f"Unexpanded templates: {self.stats['template_found']}")
        print(f"Duplicate IDs:        {self.stats['duplicate_ids']}")
        print("="*60)
        
        if self.stats['failed'] > 0:
            print(f"\n⚠️  {self.stats['failed']} playbooks failed validation")
            return False
        else:
            print("\n✅ All playbooks passed validation!")
            return True


def main():
    parser = argparse.ArgumentParser(
        description='Validate expanded playbooks for metadata and Sigma query correctness'
    )
    parser.add_argument('directory', 
                       help='Directory containing expanded playbooks to validate')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Show detailed validation output')
    parser.add_argument('--workers', '-w', type=int, default=None,
                       help=f'Number of parallel workers (default: auto, max 8)')
    parser.add_argument('--fixup', '-f', action='store_true',
                       help='Automatically fix common Sigma query structure issues')
    parser.add_argument('--reset', type=str, default=None,
                       help='Reset directory - failed playbooks will be deleted from validation dir and this dir, with backup created in ./failed/')
    parser.add_argument('--staged', action='store_true',
                       help='Only validate git staged files')
    
    args = parser.parse_args()
    
    # Determine number of workers
    workers = args.workers
    
    validator = PlaybookValidator()
    passed, failed = validator.validate_directory(args.directory, workers, args.fixup, args.reset, args.staged)
    
    # Exit with error code if any validations failed
    sys.exit(1 if failed > 0 else 0)


if __name__ == '__main__':
    main()
