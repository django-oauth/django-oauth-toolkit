"""
Custom Sphinx documentation module to link to parts of the OAuth2 RFC.
"""

from docutils import nodes


base_url = "https://rfc-editor.org/rfc/rfc6749.html"


def rfclink(name, rawtext, text, lineno, inliner, options={}, content=[]):
    """Link to the OAuth2 draft.

    Returns 2 part tuple containing list of nodes to insert into the
    document and a list of system messages.  Both are allowed to be
    empty.

    :param name: The role name used in the document.
    :param rawtext: The entire markup snippet, with role.
    :param text: The text marked with the role.
    :param lineno: The line number where rawtext appears in the input.
    :param inliner: The inliner instance that called us.
    :param options: Directive options for customization.
    :param content: The directive content for customization.
    """

    node = nodes.reference(rawtext, "RFC6749 Section " + text, refuri="%s#section-%s" % (base_url, text))

    return [node], []


def setup(app):
    """
    Install the plugin.

    :param app: Sphinx application context.
    """
    app.add_role("rfc", rfclink)
