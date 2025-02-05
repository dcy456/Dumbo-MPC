
import logging.config
import os
import yaml
import sys
from optimizedhbmpc.config import HbmpcConfig

package_dir = os.path.dirname(os.path.abspath(__file__))


logging_file = os.path.join(package_dir, 'logging.yaml')

with open(logging_file, 'r') as f:
    os.makedirs("benchmark-logs", exist_ok=True)
    logging_config = yaml.safe_load(f.read())
    logging.config.dictConfig(logging_config)
    logging.getLogger("asyncio").setLevel(logging.WARNING)

# Skip loading the config for tests since the would have different values for sys.argv.
if "pytest" not in sys.modules:
    HbmpcConfig.load_config()
