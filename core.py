import ast
from typing import List, Dict, Optional
import openai
import difflib

class CodeContext:
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        if api_key:
            openai.api_key = api_key
        self.context_cache = {}

    def parse_code(self, code: str) -> ast.AST:
        """Parse code into AST for analysis"""
        return ast.parse(code)

    def extract_context(self, code: str) -> Dict:
        """Extract key context from code including imports, functions, and classes"""
        tree = self.parse_code(code)
        context = {
            'imports': [],
            'functions': [],
            'classes': [],
            'variables': []
        }

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                context['imports'].extend(n.name for n in node.names)
            elif isinstance(node, ast.ImportFrom):
                context['imports'].append(f'{node.module}: {[n.name for n in node.names]}')
            elif isinstance(node, ast.FunctionDef):
                context['functions'].append({
                    'name': node.name,
                    'args': [a.arg for a in node.args.args],
                    'docstring': ast.get_docstring(node)
                })
            elif isinstance(node, ast.ClassDef):
                context['classes'].append({
                    'name': node.name,
                    'bases': [b.id for b in node.bases if isinstance(b, ast.Name)],
                    'docstring': ast.get_docstring(node)
                })

        return context

    def get_smart_suggestions(self, code: str, context: Dict) -> List[str]:
        """Generate AI-powered suggestions based on code context"""
        if not self.api_key:
            return ["API key required for AI suggestions"]

        prompt = f"""Given this code context:
        Imports: {context['imports']}
        Functions: {[f['name'] for f in context['functions']]}
        Classes: {[c['name'] for c in context['classes']]}
        
        Suggest improvements for:
        {code}
        """

        try:
            response = openai.ChatCompletion.create(
                model="gpt-4",
                messages=[{
                    "role": "system",
                    "content": "You are an expert code reviewer and developer. Provide specific, actionable suggestions."
                }, {
                    "role": "user",
                    "content": prompt
                }]
            )
            return [suggestion.strip() for suggestion in response.choices[0].message.content.split('\n') if suggestion.strip()]
        except Exception as e:
            return [f"Error generating suggestions: {str(e)}"]

    def analyze_changes(self, old_code: str, new_code: str) -> List[str]:
        """Analyze code changes and provide insights"""
        diff = difflib.unified_diff(
            old_code.splitlines(keepends=True),
            new_code.splitlines(keepends=True)
        )
        changes = [line for line in diff if line.startswith(('+', '-'))] 
        
        old_context = self.extract_context(old_code)
        new_context = self.extract_context(new_code)
        
        analysis = []
        
        # Analyze structural changes
        for key in ['imports', 'functions', 'classes']:
            old_items = set(str(item) for item in old_context[key])
            new_items = set(str(item) for item in new_context[key])
            
            added = new_items - old_items
            removed = old_items - new_items
            
            if added:
                analysis.append(f"Added {key}: {', '.join(added)}")
            if removed:
                analysis.append(f"Removed {key}: {', '.join(removed)}")

        return analysis

class DevMind:
    def __init__(self, api_key: Optional[str] = None):
        self.context = CodeContext(api_key)
        
    def analyze_code(self, code: str) -> Dict:
        """Analyze code and provide comprehensive insights"""
        context = self.context.extract_context(code)
        suggestions = self.context.get_smart_suggestions(code, context)
        
        return {
            'context': context,
            'suggestions': suggestions,
            'complexity': self.calculate_complexity(code),
        }
    
    def calculate_complexity(self, code: str) -> Dict:
        """Calculate various code complexity metrics"""
        tree = ast.parse(code)
        complexity = {
            'lines': len(code.splitlines()),
            'functions': len([node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)]),
            'classes': len([node for node in ast.walk(tree) if isinstance(node, ast.ClassDef)]),
            'imports': len([node for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom))])
        }
        return complexity