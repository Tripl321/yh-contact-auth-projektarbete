#!/usr/bin/env python3
"""
SHALLOT — UNO Q Key Authority Streamlit App
App Lab application for key generation and distribution

This app runs on the UNO Q's Linux MPU and communicates with the STM32U585 MCU
via Bridge RPC. It provides a web interface for:
- Key generation using hardware TRNG
- Key distribution to PLC and PAW devices
- Status monitoring

Requirements:
- Streamlit (included in UNO Q App Lab "Bricks")
- Arduino Router Bridge communication
"""

import streamlit as st
import json
import time
from typing import Optional, Dict, Any

# =============================================================
# Configuration
# =============================================================

APP_TITLE = "SHALLOT Key Authority"
APP_DESCRIPTION = """
**Secure Hardware Authentication & Key Distribution**

Manage key generation and distribution for the SHALLOT authentication system.
This app communicates with the STM32U585 MCU via Bridge RPC.

**Security Notes:**
- Keys are generated using hardware TRNG (STM32U585 RNG)
- Key material never leaves the MCU domain
- Distribution requires physical UART connections to target devices
"""

# Bridge RPC method names
BRIDGE_METHODS = {
    "get_key_state": "get_key_state",
    "get_key_fingerprint": "get_key_fingerprint", 
    "request_key_generation": "request_key_generation",
    "distribute_key_to_plc": "distribute_key_to_plc",
    "distribute_key_to_paw": "distribute_key_to_paw",
    "generate_and_distribute_all": "generate_and_distribute_all",
    "request_key_distribution": "request_key_distribution"
}

# Key state constants (matching Arduino enum)
KEY_STATES = {
    0: {"name": "UNINITIALIZED", "color": "🔴", "desc": "No key generated"},
    1: {"name": "GENERATED", "color": "🟡", "desc": "Key generated, ready for distribution"},
    2: {"name": "DISTRIBUTED (PLC)", "color": "🟠", "desc": "Key distributed to PLC"},
    3: {"name": "DISTRIBUTED (PAW)", "color": "🟠", "desc": "Key distributed to PAW"},
    4: {"name": "DISTRIBUTED (BOTH)", "color": "🟢", "desc": "Key distributed to both devices"},
    255: {"name": "ERROR", "color": "❌", "desc": "Error state"}
}

TARGET_NAMES = {
    0x01: "PLC (Raspberry Pi Pico 2)",
    0x02: "PAW (Adafruit Feather RP2350)"
}

# =============================================================
# Bridge RPC Communication Helper
# =============================================================

class BridgeRPC:
    """
    Helper class to communicate with Arduino Bridge RPC.
    The UNO Q uses a socket-based bridge for MPU-MCU communication.
    """
    
    def __init__(self):
        self.last_call_time = 0
        self.call_delay = 0.1  # Minimum delay between calls (seconds)
    
    def call(self, method: str, args: list = None) -> Any:
        """
        Call a Bridge RPC method.
        
        Args:
            method: Name of the RPC method
            args: List of arguments to pass
            
        Returns:
            Result from the RPC call
        """
        # Rate limiting
        elapsed = time.time() - self.last_call_time
        if elapsed < self.call_delay:
            time.sleep(self.call_delay - elapsed)
        self.last_call_time = time.time()
        
        # For UNO Q, Bridge RPC is accessed via the bridge socket
        # In the App Lab environment, we use the bridge module
        try:
            import bridge
            if args:
                return getattr(bridge, method)(*args)
            else:
                return getattr(bridge, method)()
        except ImportError:
            # Fallback for testing outside UNO Q
            st.warning("🔌 Bridge module not found. Using simulation mode.")
            return self._simulate_bridge_call(method, args)
        except Exception as e:
            st.error(f"❌ Bridge RPC error: {method} - {str(e)}")
            return None
    
    def _simulate_bridge_call(self, method: str, args: list = None) -> Any:
        """Simulate Bridge RPC calls for testing"""
        if method == "get_key_state":
            return 0  # UNINITIALIZED
        elif method == "get_key_fingerprint":
            return "DEADBEEF"  # Example fingerprint
        elif method == "request_key_generation":
            st.success("🎲 Simulated key generation")
            return True
        elif method in ["distribute_key_to_plc", "distribute_key_to_paw"]:
            st.success(f"📤 Simulated distribution to {method.split('_')[-2]}")
            return True
        elif method == "generate_and_distribute_all":
            return json.dumps({
                "status": "success",
                "generated": True,
                "plc_success": True,
                "paw_success": True,
                "fingerprint": "DEADBEEF"
            })
        return None

# =============================================================
# Main App
# =============================================================

def main():
    # Page configuration
    st.set_page_config(
        page_title=APP_TITLE,
        page_icon="🔐",
        layout="wide",
        initial_sidebar_state="expanded"
    )
    
    # Initialize Bridge RPC
    bridge = BridgeRPC()
    
    # Title and description
    st.title(APP_TITLE)
    st.markdown(APP_DESCRIPTION)
    
    # Sidebar
    with st.sidebar:
        st.header("🔧 System Info")
        st.markdown("""
        **Hardware:** Arduino UNO Q  
        **MCU:** STM32U585 (Hardware TRNG)  
        **MPU:** Qualcomm QRB2210 (Linux)  
        **App:** Streamlit (App Lab)
        """)
        
        st.markdown("---")
        st.header("ℹ️ Help")
        st.markdown("""
        **Commands:**
        - 🎲 **Generate Key**: Creates new AES-128 key
        - 📤 **Distribute**: Sends key to connected devices
        - 🔄 **Generate & Distribute**: One-click full workflow
        
        **Requirements:**
        - Physical UART connections to PLC/PAW
        - Device power on
        """)
    
    # Main content
    st.markdown("---")
    
    # Status section
    with st.expander("📊 **Current Status**", expanded=True):
        status_col1, status_col2, status_col3 = st.columns(3)
        
        with status_col1:
            # Get current key state
            key_state = bridge.call("get_key_state")
            state_info = KEY_STATES.get(key_state, {"name": "UNKNOWN", "color": "❓", "desc": "Unknown"})
            st.markdown(f"**Key State:** {state_info['color']} **{state_info['name']}**")
            st.caption(state_info['desc'])
        
        with status_col2:
            # Get key fingerprint
            fingerprint = bridge.call("get_key_fingerprint")
            if fingerprint:
                st.markdown(f"**Fingerprint:** `{fingerprint}`")
            else:
                st.markdown("**Fingerprint:** *No key generated*")
            st.caption("SHA-256 hash of the key (first 4 bytes)")
        
        with status_col3:
            st.markdown("**Last Action:**")
            st.caption("Recent operations will appear here")
    
    st.markdown("---")
    
    # Action buttons
    st.header("⚡ **Actions**")
    
    action_col1, action_col2 = st.columns(2)
    
    with action_col1:
        if st.button("🎲 **Generate New Key**", use_container_width=True):
            with st.spinner("Generating key using hardware TRNG..."):
                success = bridge.call("request_key_generation")
                if success:
                    st.success("✅ **Key Generated Successfully!**")
                    time.sleep(0.5)
                    # Refresh status
                    key_state = bridge.call("get_key_state")
                    fingerprint = bridge.call("get_key_fingerprint")
                    st.json({
                        "status": "generated",
                        "fingerprint": fingerprint,
                        "state": key_state
                    })
                else:
                    st.error("❌ **Key Generation Failed**")
                    st.caption("Check TRNG health or connection")
    
    with action_col2:
        if st.button("🔄 **Generate & Distribute to All**", use_container_width=True):
            with st.spinner("Generating and distributing keys..."):
                result = bridge.call("generate_and_distribute_all")
                if result:
                    try:
                        result_dict = json.loads(result)
                        st.success("✅ **Operation Complete**")
                        
                        # Display results
                        status_col1, status_col2 = st.columns(2)
                        with status_col1:
                            st.markdown(f"**Generated:** {'✅ Yes' if result_dict.get('generated') else '❌ No'}")
                            st.markdown(f"**PLC:** {'✅ Success' if result_dict.get('plc_success') else '❌ Failed'}")
                        with status_col2:
                            st.markdown(f"**PAW:** {'✅ Success' if result_dict.get('paw_success') else '❌ Failed'}")
                            st.markdown(f"**Fingerprint:** `{result_dict.get('fingerprint', 'N/A')}`")
                    except json.JSONDecodeError:
                        st.error(f"❌ Unexpected response: {result}")
                else:
                    st.error("❌ **Operation Failed**")
    
    st.markdown("---")
    
    # Individual distribution
    st.header("📤 **Distribute Key**")
    
    dist_col1, dist_col2 = st.columns(2)
    
    with dist_col1:
        if st.button("🏭 **Distribute to PLC**", use_container_width=True):
            with st.spinner("Distributing key to PLC..."):
                success = bridge.call("distribute_key_to_plc")
                if success:
                    st.success("✅ **Key Distributed to PLC!**")
                    st.json({"target": "PLC", "status": "success"})
                else:
                    st.error("❌ **PLC Distribution Failed**")
                    st.caption("Check UART connection to PLC")
    
    with dist_col2:
        if st.button("🪪 **Distribute to PAW**", use_container_width=True):
            with st.spinner("Distributing key to PAW..."):
                success = bridge.call("distribute_key_to_paw")
                if success:
                    st.success("✅ **Key Distributed to PAW!**")
                    st.json({"target": "PAW", "status": "success"})
                else:
                    st.error("❌ **PAW Distribution Failed**")
                    st.caption("Check UART connection to PAW")
    
    st.markdown("---")
    
    # Protocol information
    with st.expander("📚 **Protocol Details**"):
        st.header("Key Distribution Protocol")
        
        st.markdown("""
        The SHALLOT system uses a 4-step handshake protocol for secure key distribution:
        
        1. **Handshake**: UNO Q → Target: `0xA1` + target_id
        2. **Ready**: Target → UNO Q: `0xA2` + device_id (4 bytes)
        3. **Key Data**: UNO Q → Target: `0xA3` + key_length + AES-128 key + CRC32
        4. **Stored**: Target → UNO Q: `0xA4` + SHA-256 hash[:4] (for verification)
        
        **Security Features:**
        - ✅ Hardware TRNG (STM32U585)
        - ✅ CRC32 integrity check
        - ✅ SHA-256 hash verification
        - ✅ Fail-closed on any error
        - ✅ Key material never exposed to MPU/Linux
        """)
        
        st.markdown("**UART Configuration:**")
        st.code("Baud: 115200 | Data: 8N1 | Flow Control: None")
    
    # Device info
    with st.expander("🎯 **Target Devices**"):
        st.header("Connected Devices")
        
        st.markdown("""
        | Device | Type | UART Port | Device ID |
        |--------|------|------------|-----------|
        | PLC | Raspberry Pi Pico 2 | Serial1 (GP0/GP1) | `0x50 0x4C 0x43 0x01` |
        | PAW | Adafruit Feather RP2350 | Serial1 (TX1/RX0) | `0x50 0x41 0x57 0x01` |
        """)
        
        st.markdown("**Wiring Guide:**")
        st.markdown("""
        - UNO Q **TX (D0)** → Target **RX**
        - UNO Q **RX (D1)** → Target **TX**  
        - UNO Q **GND** → Target **GND**
        """)

# =============================================================
# Run the app
# =============================================================

if __name__ == "__main__":
    main()