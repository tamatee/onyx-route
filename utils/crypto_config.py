from .encryption_tool import EncryptionMethod, AsymmetricMethod, EncryptionConfig

# Available encryption configurations
ENCRYPTION_CONFIGS = {
    # Standard AES Configuration
    'AES_CONFIG': EncryptionConfig(
        symmetric_method=EncryptionMethod.AES,
        asymmetric_method=AsymmetricMethod.RSA,
        key_size=2048,
        block_size=16
    ),
    
    # ChaCha20 Configuration
    'CHACHA20_CONFIG': EncryptionConfig(
        symmetric_method=EncryptionMethod.CHACHA20,
        asymmetric_method=AsymmetricMethod.RSA,
        key_size=2048,
        block_size=16
    ),
    
    # Blowfish Configuration
    'BLOWFISH_CONFIG': EncryptionConfig(
        symmetric_method=EncryptionMethod.BLOWFISH,
        asymmetric_method=AsymmetricMethod.RSA,
        key_size=2048,
        block_size=8
    ),
    
    # High Security AES Configuration
    'HIGH_SECURITY_CONFIG': EncryptionConfig(
        symmetric_method=EncryptionMethod.AES,
        asymmetric_method=AsymmetricMethod.RSA,
        key_size=4096,
        block_size=16
    ),
    
    # Legacy Configuration
    'LEGACY_CONFIG': EncryptionConfig(
        symmetric_method=EncryptionMethod.BLOWFISH,
        asymmetric_method=AsymmetricMethod.RSA,
        key_size=1024,
        block_size=8
    )
}

# Set the default configuration here
# DEFAULT_CONFIG = ENCRYPTION_CONFIGS['AES_CONFIG']
DEFAULT_CONFIG = ENCRYPTION_CONFIGS['HIGH_SECURITY_CONFIG']

# Function to change configuration
def set_encryption_config(config_name):
    """
    Change the default encryption configuration.
    
    Args:
        config_name (str): Name of the configuration to use
        
    Returns:
        EncryptionConfig: The selected configuration
        
    Raises:
        ValueError: If config_name is not found
    """
    global DEFAULT_CONFIG
    
    if config_name not in ENCRYPTION_CONFIGS:
        raise ValueError(f"Unknown configuration: {config_name}. "
                       f"Available configs: {list(ENCRYPTION_CONFIGS.keys())}")
    
    DEFAULT_CONFIG = ENCRYPTION_CONFIGS[config_name]
    return DEFAULT_CONFIG