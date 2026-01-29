from oauth2_provider.scopes import SettingsScopes


def test_settings_scopes_get_available_scopes():
    scopes = SettingsScopes()
    assert set(scopes.get_available_scopes()) == {"read", "write"}


def test_settings_scopes_get_default_scopes():
    scopes = SettingsScopes()
    assert set(scopes.get_default_scopes()) == {"read", "write"}
