import os
import openai
import json

openai.api_key = os.environ['OPENAI_API_KEY']

def generate_code(prompt, max_tokens=1024):
    response = openai.Completion.create(
        engine='davinci',
        prompt=prompt,
        max_tokens=max_tokens,
        n=1,
        stop=None,
        temperature=0.7,
    )
    return response.choices[0].text.strip()

class AICodeGenerator:
    def __init__(self, model_path='./models/code_generator.json'):
        with open(model_path, 'r') as f:
            self.model = json.load(f)

    def generate(self, prompt):
        response = generate_code(prompt)
        return response

if __name__ == '__main__':
    generator = AICodeGenerator()
    code = generator.generate('Write a Python function to calculate the Fibonacci sequence up to a given number of terms.')
    print(code)