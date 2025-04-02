package malloy_auth

import rego.v1

source_name(parsed_path) := source_name if {
	some i, "queryResults" in parsed_path
    source_name := parsed_path[i + 1]
}

package_name(parsed_path) := package_name if {
	some i, "packages" in parsed_path
    package_name := parsed_path[i + 1]
}

query_name(parsed_query) := query_name if {
	query_name := object.get(parsed_query, ["queryName"], [])[0]
}

source_permitted(source_name, package_name) if {
	source_name in object.keys(object.get(data.malloy, [package_name], []))
}

package_permitted(package_name) if {
	package_name in object.keys(data.malloy)
}

query_permitted(query_name, package_name, source_name) if {
	query_name in object.get(data.malloy, [package_name, source_name, "queries"], [])
}

user_permitted_source_level(user, package_name, source_name) if {
	user in object.get(data.malloy, [package_name, source_name, "users"], [])
}

user_permitted_package_level(user, package_name) if {
	user in all_users(package_name)
}

all_users(package_name) := users if {
    users := {u | some k, v in data.malloy[package_name]; some z, x in v; z == "users"; u := x[_]}
} else = []

claims(token) := payload if {
	[_, payload, _] := io.jwt.decode(token)
}

jwt_token(auth_header) := t if {
	startswith(auth_header, "Bearer ")
	t := split(auth_header, " ")[1]
}

default allow := false

allow if {
	not query_name(input.parsed_query)
	not source_name(input.parsed_path)
    not package_name(input.parsed_path)
    extracted_claims := claims(jwt_token(input.attributes.request.http.headers.authorization))
    "run-malloy-query" in extracted_claims.aud
}

allow if {
	not query_name(input.parsed_query)
	not source_name(input.parsed_path)
    extracted_claims := claims(jwt_token(input.attributes.request.http.headers.authorization))
	pn := package_name(input.parsed_path)
    user_permitted_package_level(extracted_claims.sub, pn)
    package_permitted(pn)
}

allow if {
	not query_name(input.parsed_query)
	sn := source_name(input.parsed_path)
    pn := package_name(input.parsed_path)
    extracted_claims := claims(jwt_token(input.attributes.request.http.headers.authorization))
    user_permitted_source_level(extracted_claims.sub, pn, sn)
    package_permitted(pn)
    source_permitted(sn, pn)
}

allow if {
	qn := query_name(input.parsed_query)
	sn := source_name(input.parsed_path)
    pn := package_name(input.parsed_path)
    extracted_claims := claims(jwt_token(input.attributes.request.http.headers.authorization))
    user_permitted_source_level(extracted_claims.sub, pn, sn)
    package_permitted(pn)
    source_permitted(sn, pn)
    query_permitted(qn, pn, sn)
}
