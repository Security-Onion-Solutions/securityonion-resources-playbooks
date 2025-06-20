#!/usr/bin/env python3
"""
Batch Template Processor
Processes all playbooks from Claude's batch API output and expands template references
"""

import yaml
import sys
import argparse
from pathlib import Path
import shutil
from typing import Dict, List, Any, Optional

# Import the template engine from the same directory
sys.path.append(str(Path(__file__).parent))
from template_engine import ProductionTemplateEngine


class BatchTemplateProcessor:
    def __init__(self, template_file: str = 'working_templates.yaml'):
        """Initialize with template engine"""
        self.engine = ProductionTemplateEngine(template_file)
        self.stats = {
            'processed': 0,
            'expanded': 0,
            'errors': 0,
            'templates_found': 0
        }
    
    def process_directory(self, input_dir: str, output_dir: str) -> Dict[str, int]:
        """Process all YAML files in input directory"""
        input_path = Path(input_dir)
        output_path = Path(output_dir)
        
        if not input_path.exists():
            raise FileNotFoundError(f"Input directory not found: {input_dir}")
        
        # Create output directory
        output_path.mkdir(parents=True, exist_ok=True)
        
        print(f"📁 Processing playbooks from: {input_dir}")
        print(f"📁 Output directory: {output_dir}")
        
        # Find all YAML files
        yaml_files = list(input_path.glob("*.yaml")) + list(input_path.glob("*.yml"))
        
        if not yaml_files:
            print("⚠️  No YAML files found in input directory")
            return self.stats
        
        print(f"📊 Found {len(yaml_files)} playbook files to process")
        
        for yaml_file in yaml_files:
            try:
                self._process_file(yaml_file, output_path)
            except Exception as e:
                print(f"❌ Error processing {yaml_file.name}: {e}")
                self.stats['errors'] += 1
        
        return self.stats
    
    def _process_file(self, input_file: Path, output_dir: Path) -> None:
        """Process a single playbook file"""
        print(f"\n📄 Processing: {input_file.name}")
        self.stats['processed'] += 1
        
        # Read the file
        with open(input_file, 'r') as f:
            content = f.read()
        
        # Check if it contains templates
        if 'template:' not in content:
            print(f"  ℹ️  No templates found, copying as-is")
            # Just copy the file
            shutil.copy2(input_file, output_dir / input_file.name)
            return
        
        # Process through template engine
        try:
            # Save to temporary location for processing
            temp_file = output_dir / f"temp_{input_file.name}"
            with open(temp_file, 'w') as f:
                f.write(content)
            
            # Process with template engine
            output_file = output_dir / input_file.name
            self.engine.process_playbook_file(str(temp_file), str(output_file))
            
            # Clean up temp file
            temp_file.unlink()
            
            # Count templates
            template_count = content.count('template:')
            self.stats['templates_found'] += template_count
            self.stats['expanded'] += 1
            
            print(f"  ✅ Expanded {template_count} templates")
            
        except Exception as e:
            print(f"  ❌ Template expansion failed: {e}")
            # Copy original file on error
            shutil.copy2(input_file, output_dir / input_file.name)
            raise
    
    def print_summary(self):
        """Print processing summary"""
        print("\n" + "="*50)
        print("📊 PROCESSING SUMMARY")
        print("="*50)
        print(f"Files processed:     {self.stats['processed']}")
        print(f"Files with templates: {self.stats['expanded']}")
        print(f"Total templates:     {self.stats['templates_found']}")
        print(f"Errors:              {self.stats['errors']}")
        print("="*50)


def main():
    parser = argparse.ArgumentParser(
        description='Batch process playbooks to expand template references'
    )
    parser.add_argument('--input-dir', '-i', required=True,
                       help='Directory containing templated playbooks')
    parser.add_argument('--output-dir', '-o', required=True,
                       help='Directory for expanded playbooks')
    parser.add_argument('--template-file', '-t', 
                       default='./templates/working_templates.yaml',
                       help='Template definition file')
    
    args = parser.parse_args()
    
    try:
        processor = BatchTemplateProcessor(args.template_file)
        stats = processor.process_directory(args.input_dir, args.output_dir)
        processor.print_summary()
        
        # Exit with error if any files failed
        return 1 if stats['errors'] > 0 else 0
        
    except Exception as e:
        print(f"❌ Fatal error: {e}")
        return 1


if __name__ == '__main__':
    sys.exit(main())