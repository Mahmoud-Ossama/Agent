import os
from abc import ABC, abstractmethod
from dotenv import load_dotenv
import google.generativeai as genai
load_dotenv()
class BaseLLM(ABC):
    @abstractmethod
    def generate(self, prompt: str) -> str:
        pass

class OpenAILLM(BaseLLM):
    def __init__(self):
        import openai
        self.api_key = os.getenv("OPENAI_API_KEY")
        if not self.api_key:
            raise ValueError("OPENAI_API_KEY environment variable is not set")
        openai.api_key = self.api_key
        self.openai = openai

    def generate(self, prompt: str) -> str:
        try:
            response = self.openai.Completion.create(
                engine=os.getenv("OPENAI_ENGINE", "text-davinci-003"),
                prompt=prompt,
                max_tokens=int(os.getenv("OPENAI_MAX_TOKENS", "1000")),
                temperature=float(os.getenv("OPENAI_TEMPERATURE", "0.7")),
                n=1,
                stop=None,
            )
            return response.choices[0].text.strip()
        except Exception as e:
            return f"Error generating LLM response: {str(e)}"

import requests

class GeminiLLM(BaseLLM):
    def __init__(self):
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            raise ValueError("GEMINI_API_KEY environment variable is not set")
        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel('gemini-1.5-flash')

    def generate(self, prompt: str) -> str:
        try:
            response = self.model.generate_content(prompt)
            return response.text.strip()
        except Exception as e:
            return f"Error generating Gemini LLM response: {str(e)}"

class OllamaLLM(BaseLLM):
    def __init__(self):
        self.api_url = "http://localhost:11434/api/generate"
        # No API key assumed for local Ollama server

    def generate(self, prompt: str) -> str:
        data = {
            "prompt": prompt,
            "max_tokens": 1000,
            "temperature": 0.7
        }
        try:
            response = requests.post(self.api_url, json=data)
            response.raise_for_status()
            result = response.json()
            return result.get("text", "").strip()
        except Exception as e:
            return f"Error generating Ollama LLM response: {str(e)}"

def get_llm():
    provider = os.getenv("LLM_PROVIDER")
    if not provider:
        raise ValueError("LLM_PROVIDER environment variable is not set")
    
    provider = provider.lower()
    if provider == "openai":
        return OpenAILLM()
    elif provider == "gemini":
        return GeminiLLM()
    elif provider == "ollama":
        return OllamaLLM()
    else:
        raise ValueError(f"Unsupported LLM provider: {provider}")
