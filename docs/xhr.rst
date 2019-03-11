================
XHR (AJAX) Usage
================

If you do configure the middleware that intercepts requests and potentially
forces a refresh to refresh your session, this gets tricky with XHR requests.
Usually XHR requests (with libraries like ``fetch`` or ``jQuery.ajax``)
follow redirects by default (which is most likely a good thing). The problem
is that it can't redirect back to the OP when it's time to refresh your
session. So for XHR requests, some special handling is required by you.

.. code-block:: javascript

    // DON'T DO THIS!

    fetch('/server/api/get/stuff', {credentials: 'same-origin'})
    .then(response => {
       response.json()
       .then(stuff => {
         doSomethingWith(stuff);
       })
    });

The problem with the above code is that it's wrong to assume the XHR
response is going to be ``application/json`` if the server's middleware
insisted you need to refresh your session.

Instead watch out for a ``403 Forbidden`` response when, in conjunction,
there is a header called ``refresh_url``. Like this:

.. code-block:: javascript

    // This assumes the /server/api/* requests are intercepted by the
    // mozilla-django-oidc refresh middleware.

    fetch('/server/api/get/stuff', {credentials: 'same-origin'})
    .then(response => {
       if (response.status === 403  && response.headers.get("refresh_url")) {
         // Perhaps do something fancier than alert()
         alert("You have to refresh your authentication.")
         // Redirect the user out of this application.
         document.location.href = response.headers.get("refresh_url");
       } else {
         response.json()
         .then(stuff => {
           doSomethingWith(stuff);
         })
       }
    });

.. note::

    The refresh middleware only applies to ``GET`` requests.

You don't have to use ``document.location.href`` to redirect immediately
inside the client-side application. Perhaps you can other things like
updating the DOM to say that the user has to refresh their authentication
and provide a regular link.
