package malloy_query_execute

import rego.v1

user_exists(user) if {
	user in object.keys(data.malloy)
}

missing_sources(user, input_sources) if {
	some source in input_sources
	not source in object.get(data.malloy, user, null).sources
}

default allow := false

allow if {
	user_exists(input.user)
	not missing_sources(input.user, input.sources)
}