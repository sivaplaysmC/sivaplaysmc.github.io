Conform = require("conform")

Conform.formatters_by_ft = vim.tbl_deep_extend("force", Conform.formatters_by_ft, {
	html = { "prettier", stop_after_first = true, lsp_format = "never" },
	css = { "prettier_css", stop_after_first = true, lsp_format = "never" },
})

Conform.formatters = {
	prettier_css = {
		args = { "--stdin-filepath", "$FILENAME", "--parser", "css" },
		command = "prettier",
	},
	prettier_html = {
		args = { "--stdin-filepath", "$FILENAME", "--parser", "html" },
		command = "prettier",
	},
}
