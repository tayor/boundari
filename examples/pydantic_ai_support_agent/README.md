# Pydantic AI Support Agent

This placeholder shows the adapter shape without requiring Pydantic AI in the core
test suite.

```python
from pydantic_ai import Agent

from boundari import Boundary
from boundari.adapters.pydantic_ai import wrap_agent

agent = Agent(...)
safe_agent = wrap_agent(agent, boundary=Boundary.from_file("boundari.yaml"))
```

Install the optional dependency before building a full demo:

```bash
pip install "boundari[pydantic-ai]"
```
