package malloy_auth

import rego.v1

source_exists(source_path) if {
	source_path in object.keys(data.malloy)
}

user_exists(user, source_path) if {
	user in object.get(data.malloy, [source_path, "users"], [])
}

default allow := false

allow if {
    print("input: ", input)

	source_path := regex.find_n(`\w*\.malloy`, input.endpoint, 1)[0]
	source_exists(source_path)
	user_exists(input.user, source_path)
}
