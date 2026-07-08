// Live client-secret UX for the Application form.
//
// Shared by the front-end register/update views and the Django admin change
// form so both surfaces behave identically. It does two things:
//
//   1. Client-secret help text: the two help variants are exposed by
//      ApplicationForm as data-attributes on the hash_client_secret checkbox; as
//      the box is toggled we swap the message shown next to the client_secret
//      field. When those attributes are absent (e.g. an already-hashed secret
//      that can no longer be reverted) the server-rendered help is left as-is.
//
//   2. HS256 warning: HS256 signs tokens with the client secret as the HMAC key,
//      so the secret must be stored unhashed (Application.clean() rejects the
//      combination, but only at save time). When the algorithm is set to HS256
//      while the secret is -- or will be -- hashed, we show an inline warning
//      immediately, updating as the algorithm/checkbox/secret change.
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

    function initClientSecretHelp() {
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

    // Style inline and toggle via style.display (not the hidden attribute or a CSS
    // class): the admin's .errornote rule sets display:block, which would override
    // [hidden]{display:none} and leave the warning always visible. Inline styles win
    // regardless of the surrounding stylesheet.
    function makeWarning(text) {
        var el = document.createElement("div");
        el.className = "oauth2-hs256-warning";
        el.setAttribute("role", "alert");
        el.style.display = "none";
        el.style.margin = "6px 0";
        el.style.padding = "6px 10px";
        el.style.color = "#a94442";
        el.style.border = "1px solid #a94442";
        el.style.borderRadius = "4px";
        el.textContent = text;
        return el;
    }

    // Place the warning on its own line beneath the field's row rather than inline
    // beside it (the admin lays each field out in a flex row, so an element inserted
    // right after the input sits to its right).
    function insertUnder(field, el) {
        var row = field.closest(".form-row, .control-group, .fieldBox");
        (row || field).insertAdjacentElement("afterend", el);
    }

    function initHs256Warning() {
        var algorithmField = document.getElementById("id_algorithm");
        if (!algorithmField) {
            return;
        }
        var hs256 = algorithmField.getAttribute("data-hs256-value");
        var algorithmText = algorithmField.getAttribute("data-hs256-hashed-secret-warning");
        if (!hs256 || !algorithmText) {
            return;
        }

        var hashField = document.getElementById("id_hash_client_secret");
        var secretField = document.getElementById("id_client_secret");
        // Whether the *stored* secret is already a hash (server-provided). An already
        // hashed value stays hashed unless the user replaces it with a new plaintext
        // secret, so unchecking the box alone does not clear the misconfiguration.
        var storedHashed = algorithmField.getAttribute("data-client-secret-stored-hashed") === "true";
        var originalSecret = secretField ? secretField.value : "";

        // Flag the conflict from both sides: under the algorithm select and next to the
        // hash_client_secret checkbox.
        var warnings = [];
        var algorithmWarning = makeWarning(algorithmText);
        insertUnder(algorithmField, algorithmWarning);
        warnings.push(algorithmWarning);

        if (hashField) {
            var hashText = algorithmField.getAttribute("data-hs256-hash-checkbox-warning") || algorithmText;
            var hashWarning = makeWarning(hashText);
            insertUnder(hashField, hashWarning);
            warnings.push(hashWarning);
        }

        function secretWillBeHashed() {
            if (hashField && hashField.checked) {
                return true;
            }
            if (storedHashed && secretField && secretField.value === originalSecret) {
                return true;
            }
            return false;
        }

        function sync() {
            var invalid = algorithmField.value === hs256 && secretWillBeHashed();
            warnings.forEach(function (warning) {
                warning.style.display = invalid ? "" : "none";
            });
        }

        algorithmField.addEventListener("change", sync);
        if (hashField) {
            hashField.addEventListener("change", sync);
        }
        if (secretField) {
            secretField.addEventListener("input", sync);
        }
        sync();
    }

    function init() {
        initClientSecretHelp();
        initHs256Warning();
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init);
    } else {
        init();
    }
})();
