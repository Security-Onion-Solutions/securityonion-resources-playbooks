#!/usr/bin/env python3
"""
Production Template Engine for Security Playbooks
Converts Claude's template-based output to final YAML playbooks
"""

import yaml
import sys
import argparse
from pathlib import Path
from jinja2 import Environment, BaseLoader
from typing import Dict, List, Any, Optional

class ProductionTemplateEngine:
    def __init__(self, template_file: str = 'working_templates.yaml'):
        """Initialize with template definitions"""
        template_path = Path(template_file)
        if not template_path.exists():
            raise FileNotFoundError(f"Template file not found: {template_file}")
            
        with open(template_path, 'r') as f:
            self.template_data = yaml.safe_load(f)
        
        self.templates = self.template_data['templates']
        self.field_mappings = self.template_data.get('field_mappings', {})
        self.jinja_env = Environment(loader=BaseLoader())
        
        print(f"✅ Loaded {len(self.templates)} templates from {template_file}")
    
    def _str_presenter(self, dumper, data):
        """Custom YAML string presenter to use literal blocks for multi-line strings"""
        # Always use literal block style for query strings or any multi-line content
        if '\n' in data or (len(data) > 50 and any(keyword in data for keyword in ['aggregation:', 'logsource:', 'detection:', 'condition:', 'fields:'])):
            # Use literal block style for multi-line strings and query blocks
            return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|-')
        return dumper.represent_scalar('tag:yaml.org,2002:str', data)

    def process_playbook_file(self, input_file: str, output_file: str = None) -> str:
        """Process a template-based playbook file to final YAML"""
        input_path = Path(input_file)
        if not input_path.exists():
            raise FileNotFoundError(f"Input file not found: {input_file}")
        
        # Determine output file
        if output_file is None:
            output_file = str(input_path.with_suffix('.final.yaml'))
        
        print(f"📖 Processing: {input_file}")
        
        # Read input file (could be template-based YAML or Claude's delimited format)
        with open(input_file, 'r') as f:
            content = f.read()
        
        # Handle Claude's START/END format
        if '---START_SID_' in content and '---END_SID_' in content:
            playbook_content = self._extract_from_delimited(content)
        else:
            playbook_content = content
        
        # Parse YAML
        try:
            playbook_spec = yaml.safe_load(playbook_content)
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML in {input_file}: {e}")
        
        # Expand templates
        final_playbook = self._expand_playbook_templates(playbook_spec)
        
        # Define a custom dumper that forces literal block style for query strings
        def represent_str(dumper, data):
            """Custom string presenter to use literal blocks for multi-line strings"""
            # Always use literal block style for query strings or any multi-line content
            if '\n' in data or (len(data) > 50 and any(keyword in data for keyword in ['aggregation:', 'logsource:', 'detection:', 'condition:', 'fields:'])):
                # Use literal block style without explicit indentation indicator
                return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|')
            return dumper.represent_scalar('tag:yaml.org,2002:str', data)
        
        # Create custom dumper with proper list indentation and literal blocks
        class CustomDumper(yaml.SafeDumper):
            def increase_indent(self, flow=False, indentless=False):
                return super(CustomDumper, self).increase_indent(flow, False)
                
            def determine_block_hints(self, text):
                # Override to use plain | without any indicators
                return ''
        
        # Configure YAML to use literal blocks for multi-line strings
        CustomDumper.add_representer(str, represent_str)
        
        # Write output
        with open(output_file, 'w') as f:
            if '---START_SID_' in content:
                # Preserve the delimited format
                sid = self._extract_sid(content)
                f.write(f"---START_SID_{sid}---\n")
                yaml.dump(final_playbook, f, Dumper=CustomDumper, default_flow_style=False, sort_keys=False, indent=2, width=1000)
                f.write(f"---END_SID_{sid}---\n")
            else:
                yaml.dump(final_playbook, f, Dumper=CustomDumper, default_flow_style=False, sort_keys=False, indent=2, width=1000)
        
        print(f"✅ Generated: {output_file}")
        return output_file
    
    def _extract_from_delimited(self, content: str) -> str:
        """Extract YAML content from Claude's delimited format"""
        start_marker = content.find('---START_SID_')
        end_marker = content.find('---END_SID_')
        
        if start_marker == -1 or end_marker == -1:
            raise ValueError("Delimited format markers not found")
        
        # Find the end of the start line
        start_line_end = content.find('\n', start_marker)
        
        return content[start_line_end + 1:end_marker].strip()
    
    def _extract_sid(self, content: str) -> str:
        """Extract SID from delimited content"""
        start_marker = content.find('---START_SID_') + 13
        end_marker = content.find('---', start_marker)
        return content[start_marker:end_marker]
    
    def _expand_playbook_templates(self, playbook_spec: Dict[str, Any]) -> Dict[str, Any]:
        """Expand all templates in a playbook specification"""
        final_playbook = playbook_spec.copy()
        
        # Replace null detection_category with empty string
        if 'detection_category' in final_playbook and final_playbook['detection_category'] is None:
            final_playbook['detection_category'] = ''
        
        if 'questions' not in final_playbook:
            print("⚠️  No questions found in playbook")
            return final_playbook
        
        # Define default ranges for templates
        default_ranges = {
            'complete_request': '+/-15m',
            'process_initiated_connection': '+/-15m',
            'other_external_connections': '+/-30m',
            'host_network_activity': '+/-30m',
            'connections_to_same_c2': '+/-2h',
            'communication_pattern': '-1h',
            'search_by_image': '+/-30m',
            'file_activity_by_extension': '+/-1h',
            'files_by_process': '+/-1h',
            'persistence_registry': '+/-30m',
            'persistence_check': '+/-30m',
            'scheduled_task_creation': '+/-30m',
            'lateral_movement_check': '+/-1h',
            'lateral_movement_internal': '+/-1h',
            'remote_service_creation': '+/-30m',
            'historical_baseline': '-7d',
            'dns_before_activity': '-15m',
            'related_alerts_by_ip': '+/-2h',
            'campaign_detection': '+/-24h',
            'frequency_analysis': '-2h'
        }
        
        expanded_count = 0
        range_added_count = 0
        for i, question in enumerate(final_playbook['questions']):
            if 'query' in question:
                query = question['query']
                
                # Check for template-based queries and handle range override
                if isinstance(query, dict) and 'template' in query:
                    template_name = query['template']
                    # First check if the template itself defines a range
                    template_range = None
                    if template_name in self.templates and 'range' in self.templates[template_name]:
                        template_range = self.templates[template_name]['range']
                        # Override any existing range with template's range
                        if 'range' in question and question['range'] != template_range:
                            print(f"📅 Overriding range {question['range']} with template range {template_range} for {template_name}")
                        else:
                            print(f"📅 Using template-defined range {template_range} for {template_name}")
                        # Reconstruct question with proper field order
                        ordered_question = {}
                        if 'question' in question:
                            ordered_question['question'] = question['question']
                        if 'context' in question:
                            ordered_question['context'] = question['context']
                        # Set the template range
                        ordered_question['range'] = template_range
                        # Add any other fields that were present
                        for key, value in question.items():
                            if key not in ['question', 'context', 'range']:
                                ordered_question[key] = value
                        # Replace the question with the ordered version
                        final_playbook['questions'][i] = ordered_question
                        question = ordered_question
                        range_added_count += 1
                    # If no template range, check if we need to add a default range
                    elif 'range' not in question and template_name in default_ranges:
                        template_range = default_ranges[template_name]
                        # Reconstruct question with proper field order
                        ordered_question = {}
                        if 'question' in question:
                            ordered_question['question'] = question['question']
                        if 'context' in question:
                            ordered_question['context'] = question['context']
                        # Add the default range
                        ordered_question['range'] = template_range
                        # Add any other fields that were present
                        for key, value in question.items():
                            if key not in ['question', 'context', 'range']:
                                ordered_question[key] = value
                        # Replace the question with the ordered version
                        final_playbook['questions'][i] = ordered_question
                        question = ordered_question
                        range_added_count += 1
                        print(f"📅 Added default range {template_range} for {template_name} template")
                
                # Handle template references
                if isinstance(query, dict) and 'template' in query:
                    try:
                        expanded_query = self._expand_template(
                            query['template'],
                            query.get('params', {})
                        )
                        # Store the expanded query without extra indentation - YAML dumper will handle it
                        final_playbook['questions'][i]['query'] = expanded_query
                        expanded_count += 1
                    except Exception as e:
                        print(f"❌ Error expanding template in question {i+1}: {e}")
                        raise
                
                # Handle string queries - keep as-is since they should already use |expand syntax
                elif isinstance(query, str):
                    # String queries should already be in correct format
                    final_playbook['questions'][i]['query'] = query
                
                # Direct YAML queries (dict format) are already properly structured - no action needed
        
        print(f"🔄 Expanded {expanded_count} templates")
        if range_added_count > 0:
            print(f"📅 Added {range_added_count} default ranges")
        return final_playbook
    
    def _expand_template(self, template_name: str, params: Dict[str, Any]) -> str:
        """Expand a single template with parameters"""
        if template_name not in self.templates:
            available = ', '.join(self.templates.keys())
            raise ValueError(f"Unknown template: {template_name}. Available: {available}")
        
        template_def = self.templates[template_name]
        query_template = template_def['query']
        
        # Add default parameters for common templates
        if template_name == 'dns_before_activity' and 'lookback_minutes' not in params:
            params['lookback_minutes'] = 15
            print(f"📝 Added default lookback_minutes=15 for dns_before_activity template")
        if template_name == 'frequency_analysis' and 'target_field' not in params:
            params['target_field'] = 'dst_ip'
            print(f"📝 Added default target_field=dst_ip for frequency_analysis template")
        if template_name == 'historical_baseline':
            if 'lookback_days' not in params:
                params['lookback_days'] = 30
                print(f"📝 Added default lookback_days=30 for historical_baseline template")
            if 'category' not in params:
                params['category'] = 'network'
                print(f"📝 Added default category=network for historical_baseline template")
            if 'grouping_field' not in params:
                params['grouping_field'] = 'dst_ip'
                print(f"📝 Added default grouping_field=dst_ip for historical_baseline template")
        
        # Prepare context
        context = params.copy()
        context.update(self.field_mappings)
        
        # Handle service-specific fields
        if 'service' in params:
            service = params['service']
            if 'service_fields' in self.field_mappings:
                context['service_fields'] = self.field_mappings['service_fields'].get(service, [])
        
        # Default host variable (could be enhanced with rule analysis)
        if 'host_variable' not in context:
            context['host_variable'] = 'src_ip'
        
        # Render template
        try:
            template = self.jinja_env.from_string(query_template)
            rendered_query = template.render(**context)
            return rendered_query.strip()
        except Exception as e:
            raise ValueError(f"Template rendering failed for {template_name}: {e}")
    
    def validate_templates(self) -> bool:
        """Validate all templates can be rendered"""
        print("🔍 Validating templates...")
        
        valid = True
        for template_name, template_def in self.templates.items():
            try:
                # Test with minimal params
                test_params = {}
                params_str = str(template_def.get('params', {}))
                
                # Handle all parameter types
                if 'service' in params_str:
                    test_params['service'] = 'http'
                if 'image_names' in params_str:
                    test_params['image_names'] = ['test.exe']
                if 'extensions' in params_str:
                    test_params['extensions'] = ['.exe', '.dll']
                if 'persistence_keys' in params_str:
                    test_params['persistence_keys'] = ['Run', 'RunOnce']
                if 'lookback_days' in params_str:
                    test_params['lookback_days'] = 30
                if 'category' in params_str:
                    test_params['category'] = 'network'
                if 'service' in params_str and 'category' in params_str:
                    test_params['service'] = 'connection'
                if 'grouping_field' in params_str:
                    test_params['grouping_field'] = 'src_ip'
                if 'target_field' in params_str:
                    test_params['target_field'] = 'dst_ip'
                if 'lookback_minutes' in params_str:
                    test_params['lookback_minutes'] = 15
                
                self._expand_template(template_name, test_params)
                print(f"  ✅ {template_name}")
            except Exception as e:
                print(f"  ❌ {template_name}: {e}")
                valid = False
        
        return valid
    
    def list_templates(self):
        """List all available templates"""
        print("\n📋 Available Templates:")
        for name, template_def in self.templates.items():
            desc = template_def.get('description', 'No description')
            params = template_def.get('params', {})
            param_info = f" (params: {list(params.keys())})" if params else ""
            print(f"  • {name}: {desc}{param_info}")

def main():
    parser = argparse.ArgumentParser(description='Production Template Engine for Security Playbooks')
    parser.add_argument('command', choices=['process', 'validate', 'list'], 
                       help='Command to execute')
    parser.add_argument('--input', '-i', help='Input playbook file (for process command)')
    parser.add_argument('--output', '-o', help='Output file (optional)')
    parser.add_argument('--templates', '-t', default='working_templates.yaml',
                       help='Template file to use')
    
    args = parser.parse_args()
    
    try:
        engine = ProductionTemplateEngine(args.templates)
        
        if args.command == 'validate':
            if engine.validate_templates():
                print("✅ All templates valid")
                return 0
            else:
                print("❌ Template validation failed")
                return 1
        
        elif args.command == 'list':
            engine.list_templates()
            return 0
        
        elif args.command == 'process':
            if not args.input:
                print("❌ Input file required for process command")
                return 1
            
            output_file = engine.process_playbook_file(args.input, args.output)
            print(f"🎉 Successfully processed {args.input} → {output_file}")
            return 0
    
    except Exception as e:
        print(f"❌ Error: {e}")
        return 1

if __name__ == '__main__':
    sys.exit(main())