// Package workspace materializes an output directory for MCP file-mediated
// results (screenshots, large search dumps) and writes into it with
// kernel-enforced symlink containment via os.Root. The root is either the
// server-configured default or an agent-prepared directory passed per call as
// workspace_root — the pattern used by abuse-lookup / asn-lookup /
// voice-studio-mcp. It MUST be agent-specifiable: a hardcoded home-dir path
// breaks in sandboxes like Cowork.
package workspace
