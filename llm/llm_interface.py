import os
from abc import ABC, abstractmethod
from dotenv import load_dotenv
import time
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
        self.max_retries = int(os.getenv("GEMINI_MAX_RETRIES", "3"))
        self.retry_delay = float(os.getenv("GEMINI_RETRY_DELAY", "2.0"))

    def generate(self, prompt: str) -> str:
        last_error = None
        
        for attempt in range(self.max_retries):
            try:
                print(f"🔄 Gemini API attempt {attempt + 1}/{self.max_retries}")
                
                # Configure timeout and safety settings
                generation_config = genai.types.GenerationConfig(
                    max_output_tokens=1000,
                    temperature=0.7,
                )
                
                response = self.model.generate_content(
                    prompt, 
                    generation_config=generation_config,
                    safety_settings={
                        genai.types.HarmCategory.HARM_CATEGORY_HATE_SPEECH: genai.types.HarmBlockThreshold.BLOCK_NONE,
                        genai.types.HarmCategory.HARM_CATEGORY_HARASSMENT: genai.types.HarmBlockThreshold.BLOCK_NONE,
                        genai.types.HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT: genai.types.HarmBlockThreshold.BLOCK_NONE,
                        genai.types.HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT: genai.types.HarmBlockThreshold.BLOCK_NONE,
                    }
                )
                
                if response.text:
                    print(f"✅ Gemini API success on attempt {attempt + 1}")
                    return response.text.strip()
                else:
                    raise Exception("Empty response from Gemini API")
                    
            except Exception as e:
                last_error = e
                print(f"❌ Gemini API attempt {attempt + 1} failed: {str(e)}")
                
                if attempt < self.max_retries - 1:
                    print(f"⏳ Waiting {self.retry_delay} seconds before retry...")
                    time.sleep(self.retry_delay)
                    # Exponential backoff
                    self.retry_delay *= 1.5
        
        return f"Error generating Gemini LLM response: {str(last_error)} (failed after {self.max_retries} attempts)"

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
