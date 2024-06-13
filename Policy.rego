package tic

import future.keywords.in

# Serialize the JWKS JSON data to a string
jwks := json.marshal(data.jwks)
 
default allow = false
 
inputAttributes := { a | a := input.attributes.value[_] }

grantedAttributes (permission) = attributes {
    attributes := { g | g := permission[_] }
}

allow {
    # Update to reflect retrieving the principal SSO Id from the access token after validation.
    ssoId := verifyToken

    # Bind the user entitlements
    # principal := data.users[ssoId] # Dictionary-based
    some user in data.users
    user.ssoId == ssoId
    authorizeRequest(user)
}

#allow {
    # ssoId := verifyToken

    # Retrieve user authz data from Azure Redis Cache
        # use ssoId to request Authz data from Redis Change
    
    # Evaluate policy against response
    #authorizeRequest(response.user)

    # kick bundler into action
#}

authorizeRequest(principal) {
    # Bind the resource the user is accessing.
    resource := principal["privileges"][input.resource]

    # Bind the action (permission) the user is permforming.
    permission := resource[input.permission]

    # Confirm usage scope/attributes
    count(input.attributes.value) > 0
    allowedAttributes := grantedAttributes(permission)
    # a = { 1, 2 }, b = { 1, 3, 4, 5 }, a - b = { 2 } --> Rule will fail
    # a = { 1, 4 }, b = { 1, 3, 4, 5 }, a - b = { } --> Rule will succeed
    invalidAttributes = inputAttributes - allowedAttributes
    count(invalidAttributes) == 0
}

allowedVolumes := volumes {
    allow
    volumes := data.catalog[input.attributes.value[_]]
    #print(volumes)
}

verifyToken := ssoId {
    #[header, payload, _] := io.jwt.decode_verify(input.token, jwks)

    # Verify the RS512 signature only
    verifyOutput := io.jwt.verify_rs512(input.token, jwks)

    # Decode the JWT (without verification)
    [header, payload, _] := io.jwt.decode(input.token)
    
    # Extract and Bind SSOId
    ssoId := payload.sub
}