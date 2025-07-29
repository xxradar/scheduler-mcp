"""
Task executor for MCP Scheduler.
"""
import asyncio
import logging
import shlex
import subprocess
import platform
import os
from datetime import datetime
import aiohttp
from typing import Optional, Tuple

import openai

from .task import Task, TaskExecution, TaskStatus, TaskType, validate_command_safety

logger = logging.getLogger(__name__)


class Executor:
    """Task executor for running scheduled tasks."""
    
    def __init__(self, api_key: Optional[str] = None, model: str = "gpt-4o"):
        """Initialize the task executor."""
        self.api_key = api_key
        self.ai_model = model
        self.execution_timeout = 300  # 5 minutes default timeout
        self.is_windows = platform.system() == "Windows"
        
        if api_key:
            openai.api_key = api_key
    
    async def execute_task(self, task: Task) -> TaskExecution:
        """Execute a task based on its type."""
        logger.info(f"Executing task: {task.id} ({task.name})")
        
        execution = TaskExecution(task_id=task.id)
        
        try:
            if task.type.value == "shell_command":
                output, error = await self._execute_shell_command(task.command)
                if error:
                    execution.status = TaskStatus.FAILED
                    execution.error = error
                else:
                    execution.status = TaskStatus.COMPLETED
                    execution.output = output
                    
            elif task.type.value == "api_call":
                output, error = await self._execute_api_call(
                    task.api_url, 
                    task.api_method, 
                    task.api_headers, 
                    task.api_body
                )
                if error:
                    execution.status = TaskStatus.FAILED
                    execution.error = error
                else:
                    execution.status = TaskStatus.COMPLETED
                    execution.output = output
                    
            elif task.type.value == "ai":
                output, error = await self._execute_ai_task(task.prompt)
                if error:
                    execution.status = TaskStatus.FAILED
                    execution.error = error
                else:
                    execution.status = TaskStatus.COMPLETED
                    execution.output = output
                    
            elif task.type.value == "reminder":
                output, error = await self._execute_reminder_task(
                    task.reminder_title or task.name,
                    task.reminder_message
                )
                if error:
                    execution.status = TaskStatus.FAILED
                    execution.error = error
                else:
                    execution.status = TaskStatus.COMPLETED
                    execution.output = output
            
            else:
                execution.status = TaskStatus.FAILED
                execution.error = f"Unsupported task type: {task.type.value}"
                
        except Exception as e:
            logger.exception(f"Error executing task {task.id}")
            execution.status = TaskStatus.FAILED
            execution.error = str(e)
        
        execution.end_time = datetime.utcnow()
        return execution
    
    async def _execute_shell_command(self, command: str) -> Tuple[Optional[str], Optional[str]]:
        """Execute a shell command with timeout and security validation."""
        if not command:
            return None, "No command specified"
        
        # Validate command safety first
        is_safe, reason = validate_command_safety(command)
        if not is_safe:
            return None, f"Command rejected for security reasons: {reason}"
        
        # Determine if we need to use shell mode (only for specific cases)
        use_shell = False
        
        # Only use shell mode for specific Windows built-ins that require it
        if self.is_windows:
            windows_builtins = ['dir', 'echo', 'set', 'type', 'copy', 'del', 'md', 'rd', 'ren', 'cls', 'cd']
            command_first_word = command.strip().split()[0].lower()
            if command_first_word in windows_builtins:
                use_shell = True
        
        # For most commands, use direct execution which is safer
        logger.info(f"Executing command: {command} (shell mode: {use_shell})")
        
        try:
            if use_shell and self.is_windows:
                # Use shell mode only for Windows built-ins
                # Escape the command properly for cmd.exe
                escaped_command = shlex.quote(command) if not self.is_windows else command
                full_command = f"cmd.exe /c {escaped_command}"
                
                process = await asyncio.create_subprocess_shell(
                    full_command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
            else:
                # Use direct execution for better security
                try:
                    # Parse command into arguments safely
                    args = shlex.split(command)
                    if not args:
                        return None, "Empty command after parsing"
                        
                except ValueError as e:
                    return None, f"Invalid command syntax: {str(e)}"
                
                # Execute directly without shell
                process = await asyncio.create_subprocess_exec(
                    *args,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
            
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(), 
                    timeout=self.execution_timeout
                )
                
                if process.returncode != 0:
                    error_msg = stderr.decode().strip() if stderr else "Unknown error"
                    return None, f"Command failed with exit code {process.returncode}: {error_msg}"
                
                # Limit output size to prevent resource exhaustion
                output = stdout.decode().strip()
                if len(output) > 50000:  # Limit to 50KB
                    output = output[:50000] + "\n... (output truncated)"
                
                return output, None
                
            except asyncio.TimeoutError:
                try:
                    process.kill()
                    await process.wait()
                except Exception:
                    pass
                return None, f"Command timed out after {self.execution_timeout} seconds"
                
        except Exception as e:
            return None, f"Failed to execute command: {str(e)}"
    
    async def _execute_api_call(self, url: str, method: str, headers: dict, body: dict) -> Tuple[Optional[str], Optional[str]]:
        """Execute an API call."""
        if not url:
            return None, "No URL specified"
        
        if not method:
            method = "GET"
            
        method = method.upper()
        
        try:
            async with aiohttp.ClientSession() as session:
                request_kwargs = {
                    "headers": headers or {},
                }
                
                if method in ["POST", "PUT", "PATCH"] and body:
                    request_kwargs["json"] = body
                
                async with session.request(
                    method, 
                    url, 
                    **request_kwargs,
                    timeout=aiohttp.ClientTimeout(total=self.execution_timeout)
                ) as response:
                    response_text = await response.text()
                    
                    if response.status >= 400:
                        return None, f"API call failed with status {response.status}: {response_text}"
                    
                    return response_text, None
                    
        except aiohttp.ClientError as e:
            return None, f"API call failed: {str(e)}"
        except asyncio.TimeoutError:
            return None, f"API call timed out after {self.execution_timeout} seconds"
    
    async def _execute_ai_task(self, prompt: str) -> Tuple[Optional[str], Optional[str]]:
        """Execute an AI task using OpenAI."""
        if not prompt:
            return None, "No prompt specified"
        
        if not self.api_key:
            return None, "No API key configured for AI tasks"
        
        try:
            completion = await asyncio.to_thread(
                openai.chat.completions.create,
                model=self.ai_model,
                messages=[
                    {"role": "system", "content": "You are a helpful assistant executing scheduled tasks."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=2000
            )
            
            return completion.choices[0].message.content, None
            
        except Exception as e:
            return None, f"AI task failed: {str(e)}"
    
    async def _execute_reminder_task(self, title: str, message: str) -> Tuple[Optional[str], Optional[str]]:
        """Execute a reminder task that displays a desktop notification with sound."""
        if not message:
            return None, "No message specified for reminder"
        
        # Sanitize inputs to prevent command injection
        safe_title = self._sanitize_for_shell(title) if title else "Reminder"
        safe_message = self._sanitize_for_shell(message)
        
        if not safe_title or not safe_message:
            return None, "Title or message contains unsafe characters"
        
        os_type = platform.system()
        
        try:
            # Generate platform-specific notification commands using safe execution
            if os_type == "Windows":
                return await self._windows_notification(safe_title, safe_message)
            elif os_type == "Darwin":  # macOS
                return await self._macos_notification(safe_title, safe_message)
            else:  # Linux and others
                return await self._linux_notification(safe_title, safe_message)
                
        except Exception as e:
            logger.exception("Error in reminder task")
            return None, f"Reminder task failed: {str(e)}"
    
    def _sanitize_for_shell(self, text: str) -> str:
        """Sanitize text for safe use in shell commands."""
        if not text:
            return ""
        
        # Remove or replace dangerous characters
        import re
        # Keep only alphanumeric, spaces, and basic punctuation
        sanitized = re.sub(r'[^\w\s\-.,!?()[\]{}:;]', '', text)
        # Limit length to prevent issues
        return sanitized[:200] if sanitized else ""
    
    async def _windows_notification(self, title: str, message: str) -> Tuple[Optional[str], Optional[str]]:
        """Show Windows notification safely."""
        try:
            # Use PowerShell with proper escaping instead of VBScript/HTA
            # This is much safer than generating HTML files
            ps_command = [
                "powershell.exe",
                "-Command",
                f"Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.MessageBox]::Show('{message}', '{title}', 'OK', 'Information')"
            ]
            
            process = await asyncio.create_subprocess_exec(
                *ps_command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=self.execution_timeout
                )
                
                if process.returncode == 0:
                    # Also play a sound
                    sound_command = ["rundll32", "user32.dll,MessageBeep", "0"]
                    sound_process = await asyncio.create_subprocess_exec(
                        *sound_command,
                        stdout=asyncio.subprocess.DEVNULL,
                        stderr=asyncio.subprocess.DEVNULL
                    )
                    await sound_process.wait()
                    
                    return f"Displayed Windows notification: {title}", None
                else:
                    error_msg = stderr.decode().strip() if stderr else "Unknown error"
                    return None, f"Windows notification failed: {error_msg}"
                    
            except asyncio.TimeoutError:
                process.kill()
                return None, "Windows notification timed out"
                
        except Exception as e:
            return None, f"Windows notification error: {str(e)}"
    
    async def _macos_notification(self, title: str, message: str) -> Tuple[Optional[str], Optional[str]]:
        """Show macOS notification safely."""
        try:
            # Use osascript with proper argument array (safer than shell interpolation)
            os_command = [
                "osascript",
                "-e",
                f'display notification "{message}" with title "{title}" sound name "default"'
            ]
            
            process = await asyncio.create_subprocess_exec(
                *os_command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=self.execution_timeout
                )
                
                if process.returncode == 0:
                    return f"Displayed macOS notification: {title}", None
                else:
                    error_msg = stderr.decode().strip() if stderr else "Unknown error"
                    return None, f"macOS notification failed: {error_msg}"
                    
            except asyncio.TimeoutError:
                process.kill()
                return None, "macOS notification timed out"
                
        except Exception as e:
            return None, f"macOS notification error: {str(e)}"
    
    async def _linux_notification(self, title: str, message: str) -> Tuple[Optional[str], Optional[str]]:
        """Show Linux notification safely."""
        try:
            # Try notify-send first with proper argument array
            notify_command = ["notify-send", "-u", "normal", title, message]
            
            process = await asyncio.create_subprocess_exec(
                *notify_command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=self.execution_timeout
                )
                
                if process.returncode == 0:
                    # Try to play a sound separately
                    sound_commands = [
                        ["paplay", "/usr/share/sounds/freedesktop/stereo/message.oga"],
                        ["aplay", "/usr/share/sounds/alsa/Front_Left.wav"],
                        ["beep"],
                    ]
                    
                    for sound_cmd in sound_commands:
                        try:
                            sound_process = await asyncio.create_subprocess_exec(
                                *sound_cmd,
                                stdout=asyncio.subprocess.DEVNULL,
                                stderr=asyncio.subprocess.DEVNULL
                            )
                            await asyncio.wait_for(sound_process.wait(), timeout=2)
                            break  # If one works, we're done
                        except:
                            continue  # Try next sound command
                    
                    return f"Displayed Linux notification: {title}", None
                else:
                    # Try zenity as fallback
                    return await self._linux_zenity_notification(title, message)
                    
            except asyncio.TimeoutError:
                process.kill()
                return None, "Linux notification timed out"
                
        except Exception as e:
            return await self._linux_zenity_notification(title, message)
    
    async def _linux_zenity_notification(self, title: str, message: str) -> Tuple[Optional[str], Optional[str]]:
        """Fallback Linux notification using zenity."""
        try:
            zenity_command = ["zenity", "--info", f"--title={title}", f"--text={message}"]
            
            process = await asyncio.create_subprocess_exec(
                *zenity_command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=self.execution_timeout
                )
                
                if process.returncode == 0:
                    return f"Displayed Linux notification (zenity): {title}", None
                else:
                    return None, f"No suitable notification method found on Linux"
                    
            except asyncio.TimeoutError:
                process.kill()
                return None, "Linux zenity notification timed out"
                
        except Exception as e:
            return None, f"Linux notification fallback failed: {str(e)}"