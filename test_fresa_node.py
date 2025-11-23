"""Unit tests for the FRESA node signal monitoring system."""

import time
import unittest
from unittest.mock import patch
from io import StringIO

from fresa_node import (
    FresaNode,
    auto_record_loop,
    ATLAS_FREQ,
    TRIGGER_RMS,
    SCAN_INTERVAL,
    THETA_BAND,
)


class FresaNodeTests(unittest.TestCase):
    """Test cases for the FresaNode class."""
    
    def test_initialization(self):
        """Test that a FresaNode initializes with correct attributes."""
        node = FresaNode("TEST_LOCATION")
        self.assertEqual(node.location, "TEST_LOCATION")
        self.assertEqual(node.status, "LISTENING")
    
    def test_scan_returns_signal_strength(self):
        """Test that scan() returns a numeric signal strength value."""
        node = FresaNode("TEST_LOCATION")
        rms = node.scan(ATLAS_FREQ)
        self.assertIsInstance(rms, float)
        self.assertGreaterEqual(rms, 0.0)
    
    def test_scan_noise_floor_range(self):
        """Test that scan noise floor stays within expected bounds."""
        node = FresaNode("TEST_LOCATION")
        # Sample multiple scans to check distribution
        samples = [node.scan(ATLAS_FREQ) for _ in range(50)]
        # All samples should be positive
        self.assertTrue(all(s >= 0.0 for s in samples))
        # At least some should be below threshold (noise floor periods)
        self.assertTrue(any(s < TRIGGER_RMS for s in samples))
        # At least some should be above threshold (signal boost periods)
        self.assertTrue(any(s > TRIGGER_RMS for s in samples))
    
    @patch('fresa_node.time.time')
    def test_scan_glitch_window_timing(self, mock_time):
        """Test that signal boost occurs during specific timing windows."""
        node = FresaNode("TEST_LOCATION")
        
        # Test when time gives even result for int(time * 2) % 2
        mock_time.return_value = 1.0  # int(1.0 * 2) % 2 = 0 (even)
        rms_even = node.scan(ATLAS_FREQ)
        # During glitch window, signal should be boosted
        self.assertGreater(rms_even, TRIGGER_RMS)
        
        # Test when time gives odd result
        mock_time.return_value = 1.5  # int(1.5 * 2) % 2 = 1 (odd)
        rms_odd = node.scan(ATLAS_FREQ)
        # Outside glitch window, just noise floor
        self.assertLessEqual(rms_odd, 0.6)  # Max noise is 0.6


class AutoRecordLoopTests(unittest.TestCase):
    """Test cases for the auto_record_loop function."""
    
    @patch('fresa_node.time.sleep')
    @patch('fresa_node.FresaNode.scan')
    @patch('sys.stdout', new_callable=StringIO)
    def test_loop_detects_signal_above_threshold(self, mock_stdout, mock_scan, mock_sleep):
        """Test that the loop detects and logs signals above threshold."""
        # Set up mock to return high signal then raise KeyboardInterrupt
        mock_scan.side_effect = [0.8, KeyboardInterrupt()]
        
        # Run the loop (will exit on KeyboardInterrupt)
        auto_record_loop()
        
        output = mock_stdout.getvalue()
        # Check initialization messages
        self.assertIn("FRESA NODE CONNECTED", output)
        self.assertIn("QUEBRADA_SECA_Sim_01", output)
        self.assertIn(f"TARGET FREQ: {ATLAS_FREQ}", output)
        # Check recording detection
        self.assertIn("[REC] SIGNAL DETECTED", output)
        self.assertIn("RMS 0.800", output)
        self.assertIn(f"MATCHING PATTERN: {THETA_BAND}", output)
        # Check clean disconnect
        self.assertIn("FRESA DISCONNECTED", output)
    
    @patch('fresa_node.time.sleep')
    @patch('fresa_node.FresaNode.scan')
    @patch('sys.stdout', new_callable=StringIO)
    def test_loop_ignores_signal_below_threshold(self, mock_stdout, mock_scan, mock_sleep):
        """Test that the loop doesn't trigger recording for low signals."""
        # Set up mock to return low signal then raise KeyboardInterrupt
        mock_scan.side_effect = [0.3, KeyboardInterrupt()]
        
        # Run the loop
        auto_record_loop()
        
        output = mock_stdout.getvalue()
        # Should not contain recording message
        self.assertNotIn("[REC] SIGNAL DETECTED", output)
    
    @patch('fresa_node.time.sleep')
    @patch('fresa_node.FresaNode.scan')
    @patch('sys.stdout', new_callable=StringIO)
    def test_loop_detects_signal_loss(self, mock_stdout, mock_scan, mock_sleep):
        """Test that the loop detects when signal drops below threshold."""
        # Start with high signal, then low, then interrupt
        mock_scan.side_effect = [0.9, 0.3, KeyboardInterrupt()]
        
        # Run the loop
        auto_record_loop()
        
        output = mock_stdout.getvalue()
        # Should show both recording start and stop
        self.assertIn("[REC] SIGNAL DETECTED", output)
        self.assertIn("[STOP] SIGNAL LOST", output)
        self.assertIn("WAITING FOR GLITCH", output)
    
    @patch('fresa_node.time.sleep')
    @patch('fresa_node.FresaNode.scan')
    @patch('sys.stdout', new_callable=StringIO)
    def test_loop_maintains_recording_state(self, mock_stdout, mock_scan, mock_sleep):
        """Test that recording state is maintained for consecutive high signals."""
        # Multiple high signals, then interrupt
        mock_scan.side_effect = [0.9, 0.85, 0.88, KeyboardInterrupt()]
        
        # Run the loop
        auto_record_loop()
        
        output = mock_stdout.getvalue()
        # Should only show one recording start message
        self.assertEqual(output.count("[REC] SIGNAL DETECTED"), 1)
    
    @patch('fresa_node.time.sleep')
    @patch('fresa_node.FresaNode.scan')
    def test_loop_uses_correct_scan_interval(self, mock_scan, mock_sleep):
        """Test that the loop sleeps for the correct interval."""
        mock_scan.side_effect = [0.5, KeyboardInterrupt()]
        
        # Run the loop
        auto_record_loop()
        
        # Verify sleep was called with correct interval
        mock_sleep.assert_called_with(SCAN_INTERVAL)


class ConstantsTests(unittest.TestCase):
    """Test cases to verify module constants are properly defined."""
    
    def test_constants_are_defined(self):
        """Test that all required constants exist with expected types."""
        self.assertIsInstance(ATLAS_FREQ, int)
        self.assertEqual(ATLAS_FREQ, 5184)
        
        self.assertIsInstance(TRIGGER_RMS, float)
        self.assertEqual(TRIGGER_RMS, 0.577)
        
        self.assertIsInstance(SCAN_INTERVAL, float)
        self.assertEqual(SCAN_INTERVAL, 0.5)
        
        self.assertIsInstance(THETA_BAND, float)
        self.assertEqual(THETA_BAND, 8.4)


if __name__ == "__main__":
    unittest.main()
