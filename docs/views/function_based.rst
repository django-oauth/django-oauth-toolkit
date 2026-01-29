Function-based views
====================

Django OAuth Toolkit provides decorators to help you in protecting your function-based views.

.. function:: protected_resource(scopes=None, validator_cls=OAuth2Validator, server_cls=Server)

    Decorator to protect views by providing OAuth2 authentication out of the box, optionally with
    scope handling. Basic usage, without using scopes::

        from oauth2_provider.decorators import protected_resource

        @protected_resource()
        def my_view(request):
            # An access token is required to get here...
            # ...
            pass

    If you want to check scopes as well when accessing a view you can pass them along as
    decorator's parameter::

        from oauth2_provider.decorators import protected_resource

        @protected_resource(scopes=['can_make_it can_break_it'])
        def my_view(request):
            # An access token AND the right scopes are required to get here...
            # ...
            pass

    The decorator also accept server and validator classes if you want or need to use your own
    OAuth2 logic::

        from oauth2_provider.decorators import protected_resource
        from myapp.oauth2_validators import MyValidator

        @protected_resource(validator_cls=MyValidator)
        def my_view(request):
            # You have to leverage your own logic to get here...
            # ...
            pass


.. function:: rw_protected_resource(scopes=None, validator_cls=OAuth2Validator, server_cls=Server)

    Decorator to protect views by providing OAuth2 authentication and read/write scopes out of the
    box. ``GET``, ``HEAD``, ``OPTIONS`` HTTP methods require ``'read'`` scope.
    Otherwise ``'write'`` scope is required::

        from oauth2_provider.decorators import rw_protected_resource

        @rw_protected_resource()
        def my_view(request):
            # If this is a POST, you have to provide 'write' scope to get here...
            # ...
            pass

    If you need, you can ask for other scopes over ``'read'`` and ``'write'``::

        from oauth2_provider.decorators import rw_protected_resource

        @rw_protected_resource(scopes=['exotic_scope'])
        def my_view(request):
            # If this is a POST, you have to provide 'exotic_scope write' scopes to get here...
            # ...
            pass
