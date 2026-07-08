// Live client-secret help text for the Application form.
//
// Shared by the front-end register/update views and the Django admin change
// form so both surfaces behave identically. The two help variants are exposed
// by ApplicationForm as data-attributes on the hash_client_secret checkbox; as
// the box is toggled we swap the message shown next to the client_secret field.
// When those attributes are absent (e.g. an already-hashed secret that can no
// longer be reverted) the server-rendered help text is left untouched.
(function () {
    "use strict";

    function findHelp(secretField) {
        // Django admin renders <div class="help" id="<field-id>_helptext">.
        var byId = document.getElementById(secretField.id + "_helptext");
        if (byId) {
            return byId;
        }
        // Front-end application_form.html renders <span class="help-block"> in
        // the field's .controls wrapper.
        var controls = secretField.closest(".controls");
        if (controls) {
            return controls.querySelector(".help-block");
        }
        return null;
    }

    function textTarget(help) {
        // Newer Django admin wraps the help text in an inner <div>; write there
        // so the surrounding markup is preserved. Older admin and the front-end
        // put the text directly in the element itself.
        var inner = help.firstElementChild;
        if (inner && inner.tagName === "DIV") {
            return inner;
        }
        return help;
    }

    function init() {
        var hashField = document.getElementById("id_hash_client_secret");
        var secretField = document.getElementById("id_client_secret");
        if (!hashField || !secretField) {
            return;
        }

        var whenHashed = hashField.getAttribute("data-client-secret-help-when-hashed");
        var whenUnhashed = hashField.getAttribute("data-client-secret-help-when-unhashed");
        if (whenHashed === null || whenUnhashed === null) {
            return;
        }

        var help = findHelp(secretField);
        if (!help) {
            return;
        }
        var target = textTarget(help);

        function sync() {
            target.textContent = hashField.checked ? whenHashed : whenUnhashed;
        }

        hashField.addEventListener("change", sync);
        sync();
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init);
    } else {
        init();
    }
})();
