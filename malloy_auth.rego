package malloy_auth

import rego.v1

package_exists(package_name) if {
	package_name in object.keys(data.malloy)
}

user_exists(user, package_name) if {
	user in object.get(data.malloy, [package_name, "users"], [])
}

query_name_exists(package_name, query_name) if {
	query_name in object.get(data.malloy, [package_name, "queries"], [])
}

default allow := false

claims := payload if {
	[_, payload, _] := io.jwt.decode(jwt_token)
}

jwt_token := t if {
	v := input.attributes.request.http.headers.authorization
	startswith(v, "Bearer ")
	t := split(v, " ")[1]
}

allow if {
	package_name := [p | p := input.parsed_path[_]; regex.match(`^.*\.malloy$`, p)][0]
	package_exists(package_name)
    query_name_exists(package_name, input.parsed_query.queryName[0])
	user_exists(claims.sub, package_name)
}
