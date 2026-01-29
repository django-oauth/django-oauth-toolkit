apps_in_beta = {"some_other_app", "this_one_too"}

# These are bare minimum routers to fake the scenario where there is actually a
# decision around where an application's models might live.


class AlphaRouter:
    # alpha is where the core Django models are stored including user. To keep things
    # simple this is where the oauth2 provider models are stored as well because they
    # have a foreign key to User.

    def db_for_read(self, model, **hints):
        if model._meta.app_label not in apps_in_beta:
            return "alpha"
        return None

    def db_for_write(self, model, **hints):
        if model._meta.app_label not in apps_in_beta:
            return "alpha"
        return None

    def allow_relation(self, obj1, obj2, **hints):
        if obj1._state.db == "alpha" and obj2._state.db == "alpha":
            return True
        return None

    def allow_migrate(self, db, app_label, model_name=None, **hints):
        if app_label not in apps_in_beta:
            return db == "alpha"
        return None


class BetaRouter:
    def db_for_read(self, model, **hints):
        if model._meta.app_label in apps_in_beta:
            return "beta"
        return None

    def db_for_write(self, model, **hints):
        if model._meta.app_label in apps_in_beta:
            return "beta"
        return None

    def allow_relation(self, obj1, obj2, **hints):
        if obj1._state.db == "beta" and obj2._state.db == "beta":
            return True
        return None

    def allow_migrate(self, db, app_label, model_name=None, **hints):
        if app_label in apps_in_beta:
            return db == "beta"


class CrossDatabaseRouter:
    # alpha is where the core Django models are stored including user. To keep things
    # simple this is where the oauth2 provider models are stored as well because they
    # have a foreign key to User.
    def db_for_read(self, model, **hints):
        if model._meta.model_name == "accesstoken":
            return "beta"
        return None

    def db_for_write(self, model, **hints):
        if model._meta.model_name == "accesstoken":
            return "beta"
        return None

    def allow_relation(self, obj1, obj2, **hints):
        if obj1._state.db == "beta" and obj2._state.db == "beta":
            return True
        return None

    def allow_migrate(self, db, app_label, model_name=None, **hints):
        if model_name == "accesstoken":
            return db == "beta"
        return None
