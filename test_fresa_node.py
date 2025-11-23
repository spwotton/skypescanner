"""Tests for the FRESA node signal detection simulation."""

import time
import unittest
from unittest.mock import patch

from fresa_node import (
    ATLAS_FREQ,
    CARRIER_LOW,
    THETA_BAND,
    TRIGGER_RMS,
    SCAN_INTERVAL,
    FresaNode,
    auto_record_loop,
)


class FresaNodeConstantsTests(unittest.TestCase):
    """Test that FRESA node constants are properly defined."""
    
    def test_atlas_freq_is_positive(self):
        """ATLAS_FREQ should be a positive value representing kHz."""
        self.assertGreater(ATLAS_FREQ, 0)
        self.assertEqual(ATLAS_FREQ, 5184)
    
    def test_carrier_low_is_defined(self):
        """CARRIER_LOW should be defined."""
        self.assertEqual(CARRIER_LOW, 159)
    
    def test_theta_band_is_defined(self):
        """THETA_BAND should be defined as the V2K modulation."""
        self.assertEqual(THETA_BAND, 8.4)
    
    def test_trigger_rms_is_threshold(self):
        """TRIGGER_RMS should be the detection threshold."""
        self.assertEqual(TRIGGER_RMS, 0.577)
    
    def test_scan_interval_is_half_second(self):
        """SCAN_INTERVAL should be 0.5 seconds."""
        self.assertEqual(SCAN_INTERVAL, 0.5)


class FresaNodeTests(unittest.TestCase):
    """Test the FresaNode class."""
    
    def test_init_sets_location(self):
        """Node should store its location on initialization."""
        node = FresaNode("TEST_LOCATION_01")
        self.assertEqual(node.location, "TEST_LOCATION_01")
    
    def test_init_sets_listening_status(self):
        """Node should have LISTENING status on initialization."""
        node = FresaNode("TEST_LOCATION_02")
        self.assertEqual(node.status, "LISTENING")
    
    def test_scan_returns_float(self):
        """scan() should return a float value."""
        node = FresaNode("TEST_LOCATION_03")
        result = node.scan(ATLAS_FREQ)
        self.assertIsInstance(result, float)
    
    def test_scan_returns_positive_value(self):
        """scan() should return a positive RMS value."""
        node = FresaNode("TEST_LOCATION_04")
        result = node.scan(ATLAS_FREQ)
        self.assertGreater(result, 0.0)
    
    def test_scan_signal_strength_varies_with_time(self):
        """scan() should return varying signal strengths based on timing."""
        node = FresaNode("TEST_LOCATION_05")
        
        # Collect multiple samples
        samples = []
        for _ in range(10):
            samples.append(node.scan(ATLAS_FREQ))
            time.sleep(0.1)
        
        # Should have variation in samples
        self.assertGreater(max(samples), min(samples))
    
    def test_scan_sometimes_exceeds_threshold(self):
        """scan() should sometimes return values above TRIGGER_RMS."""
        node = FresaNode("TEST_LOCATION_06")
        
        # Try multiple scans
        above_threshold_found = False
        for _ in range(20):
            rms = node.scan(ATLAS_FREQ)
            if rms > TRIGGER_RMS:
                above_threshold_found = True
                break
            time.sleep(0.1)
        
        self.assertTrue(above_threshold_found, 
                       "Expected to find at least one scan above threshold")
    
    def test_scan_sometimes_below_threshold(self):
        """scan() should sometimes return values below TRIGGER_RMS."""
        node = FresaNode("TEST_LOCATION_07")
        
        # Try multiple scans
        below_threshold_found = False
        for _ in range(20):
            rms = node.scan(ATLAS_FREQ)
            if rms < TRIGGER_RMS:
                below_threshold_found = True
                break
            time.sleep(0.1)
        
        self.assertTrue(below_threshold_found,
                       "Expected to find at least one scan below threshold")


class AutoRecordLoopTests(unittest.TestCase):
    """Test the auto_record_loop function."""
    
    @patch('fresa_node.time.sleep')
    @patch('fresa_node.FresaNode')
    def test_auto_record_loop_creates_node(self, mock_node_class, mock_sleep):
        """auto_record_loop should create a FresaNode instance."""
        # Configure mock to return proper values
        mock_node = mock_node_class.return_value
        mock_node.location = "QUEBRADA_SECA_Sim_01"
        mock_node.scan.return_value = 0.5  # Below threshold
        
        # Make the loop exit after first iteration
        mock_sleep.side_effect = KeyboardInterrupt()
        
        try:
            auto_record_loop()
        except KeyboardInterrupt:
            pass
        
        mock_node_class.assert_called_once_with("QUEBRADA_SECA_Sim_01")
    
    @patch('fresa_node.time.sleep')
    @patch('builtins.print')
    def test_auto_record_loop_prints_startup_info(self, mock_print, mock_sleep):
        """auto_record_loop should print node connection info."""
        # Make the loop exit after first iteration
        mock_sleep.side_effect = KeyboardInterrupt()
        
        try:
            auto_record_loop()
        except KeyboardInterrupt:
            pass
        
        # Check that startup messages were printed
        calls = [str(call) for call in mock_print.call_args_list]
        startup_messages = [c for c in calls if 'FRESA NODE CONNECTED' in c or 'TARGET FREQ' in c]
        self.assertGreater(len(startup_messages), 0)
    
    @patch('fresa_node.time.sleep')
    @patch('builtins.print')
    def test_auto_record_loop_handles_keyboard_interrupt(self, mock_print, mock_sleep):
        """auto_record_loop should handle KeyboardInterrupt gracefully."""
        # Make the loop exit immediately
        mock_sleep.side_effect = KeyboardInterrupt()
        
        # Should not raise exception
        try:
            auto_record_loop()
        except KeyboardInterrupt:
            self.fail("auto_record_loop should handle KeyboardInterrupt")
        
        # Check disconnect message was printed
        calls = [str(call) for call in mock_print.call_args_list]
        disconnect_messages = [c for c in calls if 'FRESA DISCONNECTED' in c]
        self.assertGreater(len(disconnect_messages), 0)


if __name__ == "__main__":
    unittest.main()
