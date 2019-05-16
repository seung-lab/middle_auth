// returns a token to be used with services that use the given auth service
async function authorize(auth_url) {
	const oauth_uri = await fetch(`https://${auth_url}/authorize?redirect=${encodeURI(window.location.origin + '/redirect.html')}`, {
		credentials: 'include'
	}).then((res) => {
		return res.text();
	});

	const auth_popup = window.open(oauth_uri);

	if (!auth_popup) {
		alert('Allow popups on this page to authenticate');
		return;
	}

	return new Promise((f, r) => {
		const tokenListener = (ev) => {
			if (ev.source === auth_popup) {
				auth_popup.close();
				window.removeEventListener("message", tokenListener);
				f(ev.data.token);
			}
		}
		
		window.addEventListener("message", tokenListener);
	});
}

function parseWWWAuthHeader(headerVal) {
	const tuples = headerVal.split('Bearer ')[1].split(', ').map((x) => x.split('='));
	const wwwAuthMap = {};

	for ([key, val] of tuples) {
		wwwAuthMap[key] = val.replace(/"/g,"");
	}

	return wwwAuthMap;
}

function authFetch(input, init, retry = 1) {
	if (!input) {
		return fetch(input); // to keep the errors consistent
	}

	const token = localStorage.getItem('auth_token');

	options = init ? JSON.parse(JSON.stringify(init)) : {};
	
	if (token) {
		options.headers = options.headers || new Headers();

		// Headers object seems to be the correct format but a regular object is supported as well
		if (options.headers instanceof Headers) {
			options.headers.append('Authorization', `Bearer ${token}`);
		} else {
			options.headers['Authorization'] = `Bearer ${token}`;
		}
	}

	return fetch(input, options).then((res) => {
		if ([400, 401].includes(res.status)) {
			const wwwAuth = res.headers.get('WWW-Authenticate');

			if (wwwAuth) {
				if (wwwAuth.startsWith('Bearer ')) {
					const wwwAuthMap = parseWWWAuthHeader(wwwAuth);

					if (!wwwAuthMap.error || wwwAuthMap.error === 'invalid_token') {
						// missing or expired
						if (retry > 0) {
							return reauthenticate(wwwAuthMap.realm).then(() => {
								return authFetch(input, init, retry - 1);
							});
						}
					}

					throw new Error(`status ${res.status} auth error - ${wwwAuthMap.error} + " Reason: ${wwwAuthMap.error_description}`);
				}
			}
		}

		return res;
	});
}

function reauthenticate(realm) {
	return authorize(realm).then((token) => {
		localStorage.setItem('auth_token', token);
	});
}

authFetch('https://dev.dynamicannotationframework.com/auth/test').then((res) => {
	return res.json();
}).then((userData) => {
	alert(`User ID: ${JSON.stringify(userData)}`);
});
