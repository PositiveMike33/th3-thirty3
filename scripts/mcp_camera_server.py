#!/usr/bin/env python3
"""
MCP Camera Tools Server
Model Context Protocol server for camera reconnaissance tools
Author: Th3Thirty3
Version: 1.0.0
"""

import json
import sys
import asyncio
from typing import Any, Dict, List
from mcp_camera_scanner import MCPCameraScanner

# MCP Protocol Implementation
class MCPCameraServer:
    """
    MCP Server for Camera Reconnaissance Tools
    Implements the Model Context Protocol for LLM integration
    """
    
    def __init__(self):
        self.scanner = MCPCameraScanner()
        self.tools = self._register_tools()
        
    def _register_tools(self) -> Dict[str, callable]:
        """Register available MCP tools"""
        return {
            "network_scan": self.scanner.mcp_network_scan,
            "arp_scan": self.scanner.mcp_arp_scan,
            "rtsp_scan": self.scanner.mcp_rtsp_scan,
            "http_fingerprint": self.scanner.mcp_http_fingerprint,
            "onvif_discover": self.scanner.mcp_onvif_discover,
            "full_audit": self.scanner.mcp_full_audit,
        }
    
    def handle_request(self, request: Dict) -> Dict:
        """Handle incoming MCP request"""
        method = request.get("method")
        params = request.get("params", {})
        request_id = request.get("id")
        
        if method == "initialize":
            return self._handle_initialize(request_id)
        elif method == "tools/list":
            return self._handle_tools_list(request_id)
        elif method == "tools/call":
            return self._handle_tool_call(request_id, params)
        else:
            return self._error_response(request_id, -32601, f"Method not found: {method}")
    
    def _handle_initialize(self, request_id: Any) -> Dict:
        """Handle initialize request"""
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {}
                },
                "serverInfo": {
                    "name": "camera-scanner",
                    "version": "1.0.0"
                }
            }
        }
    
    def _handle_tools_list(self, request_id: Any) -> Dict:
        """Handle tools/list request"""
        tools = [
            {
                "name": "network_scan",
                "description": "Scan network for devices with camera-related ports open (554, 80, 8080, 8000)",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "subnet": {
                            "type": "string",
                            "description": "Network subnet in CIDR notation (e.g., 192.168.1.0/24)",
                            "default": "192.168.1.0/24"
                        },
                        "ports": {
                            "type": "array",
                            "items": {"type": "integer"},
                            "description": "List of ports to scan",
                            "default": [80, 443, 554, 8000, 8080]
                        }
                    }
                }
            },
            {
                "name": "arp_scan",
                "description": "Perform ARP scan to discover device MAC addresses and identify camera manufacturers",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "interface": {
                            "type": "string",
                            "description": "Network interface to use (optional)"
                        }
                    }
                }
            },
            {
                "name": "rtsp_scan",
                "description": "Scan for accessible RTSP stream endpoints on a target device",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "IP address of the target device"
                        },
                        "port": {
                            "type": "integer",
                            "description": "RTSP port (default: 554)",
                            "default": 554
                        }
                    },
                    "required": ["target"]
                }
            },
            {
                "name": "http_fingerprint",
                "description": "Fingerprint HTTP service to identify camera manufacturer and model",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "IP address of the target device"
                        },
                        "port": {
                            "type": "integer",
                            "description": "HTTP port (default: 80)",
                            "default": 80
                        }
                    },
                    "required": ["target"]
                }
            },
            {
                "name": "onvif_discover",
                "description": "Discover ONVIF-compatible camera devices via WS-Discovery protocol",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "timeout": {
                            "type": "integer",
                            "description": "Discovery timeout in seconds",
                            "default": 5
                        }
                    }
                }
            },
            {
                "name": "full_audit",
                "description": "Perform comprehensive camera network audit including all discovery methods",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "subnet": {
                            "type": "string",
                            "description": "Network subnet to audit",
                            "default": "192.168.1.0/24"
                        },
                        "include_rtsp": {
                            "type": "boolean",
                            "description": "Include RTSP endpoint scanning",
                            "default": True
                        },
                        "include_onvif": {
                            "type": "boolean",
                            "description": "Include ONVIF device discovery",
                            "default": True
                        }
                    }
                }
            }
        ]
        
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {"tools": tools}
        }
    
    def _handle_tool_call(self, request_id: Any, params: Dict) -> Dict:
        """Handle tools/call request"""
        tool_name = params.get("name")
        arguments = params.get("arguments", {})
        
        if tool_name not in self.tools:
            return self._error_response(
                request_id, -32602, f"Unknown tool: {tool_name}"
            )
        
        try:
            result = self.tools[tool_name](**arguments)
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(result, indent=2)
                        }
                    ]
                }
            }
        except Exception as e:
            return self._error_response(request_id, -32603, str(e))
    
    def _error_response(self, request_id: Any, code: int, message: str) -> Dict:
        """Generate error response"""
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {
                "code": code,
                "message": message
            }
        }
    
    async def run_stdio(self):
        """Run server using stdio transport"""
        print("MCP Camera Scanner Server started", file=sys.stderr)
        
        while True:
            try:
                line = await asyncio.get_event_loop().run_in_executor(
                    None, sys.stdin.readline
                )
                if not line:
                    break
                    
                request = json.loads(line)
                response = self.handle_request(request)
                print(json.dumps(response))
                sys.stdout.flush()
                
            except json.JSONDecodeError:
                continue
            except Exception as e:
                print(f"Error: {e}", file=sys.stderr)


def main():
    """Entry point"""
    server = MCPCameraServer()
    asyncio.run(server.run_stdio())


if __name__ == "__main__":
    main()
