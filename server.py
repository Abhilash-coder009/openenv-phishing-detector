"""
Phishing Email Detector - OpenEnv HTTP Server
Clean server - no auto-run code
"""

import os
import json
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import only what we need
from inference import PhishingEnvironment, load_dataset, Action

# Global environment
env = None

class OpenEnvHandler(BaseHTTPRequestHandler):
    
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        
        if parsed.path == "/reset":
            self._handle_reset()
        elif parsed.path == "/state":
            self._handle_state()
        elif parsed.path == "/":
            self._handle_root()
        else:
            self._send_error(404, "Not Found")
    
    def do_POST(self):
        if self.path == "/step":
            self._handle_step()
        else:
            self._send_error(404, "Not Found")
    
    def _handle_reset(self):
        global env
        try:
            if env is None:
                dataset = load_dataset()
                env = PhishingEnvironment(dataset)
            obs = env.reset()
            self._send_json({"status": "ok", "observation": obs.dict()})
        except Exception as e:
            self._send_error(500, str(e))
    
    def _handle_state(self):
        global env
        try:
            if env is None:
                dataset = load_dataset()
                env = PhishingEnvironment(dataset)
            state = env.state()
            self._send_json(state.dict())
        except Exception as e:
            self._send_error(500, str(e))
    
    def _handle_step(self):
        global env
        try:
            if env is None:
                dataset = load_dataset()
                env = PhishingEnvironment(dataset)
            
            length = int(self.headers.get('Content-Length', 0))
            data = self.rfile.read(length)
            action_data = json.loads(data)
            
            action = Action(**action_data)
            obs, reward, done, state = env.step(action)
            
            self._send_json({
                "observation": obs.dict(),
                "reward": reward,
                "done": done,
                "state": state.dict()
            })
        except Exception as e:
            self._send_error(500, str(e))
    
    def _handle_root(self):
        self._send_json({
            "name": "Phishing Email Detector",
            "version": "1.0.0",
            "status": "running",
            "endpoints": ["GET /reset", "POST /step", "GET /state"]
        })
    
    def _send_json(self, data):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())
    
    def _send_error(self, code, msg):
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps({"error": msg}).encode())
    
    def log_message(self, fmt, *args):
        pass

def main():
    port = int(os.environ.get('PORT', 7860))
    
    print("\n" + "="*60)
    print("🔐 Phishing Email Detector - OpenEnv Server")
    print("="*60)
    print(f"🚀 Server running on port {port}")
    print("📡 Endpoints: /reset, /step, /state")
    print("="*60)
    print("✅ Ready for requests!\n")
    
    server = HTTPServer(('0.0.0.0', port), OpenEnvHandler)
    server.serve_forever()

if __name__ == "__main__":
    main()