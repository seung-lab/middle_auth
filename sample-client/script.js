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

		function addHeader(key, value) {
			if (options.headers instanceof Headers) {
				options.headers.append(key, value);
			} else {
				options.headers[key] = value;
			}
		}

		addHeader('Authorization', `Bearer ${token}`);
		addHeader('X-Requested-With', `Fetch`);
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

async function reauthenticate(realm) {
	const token = await authorize(realm);
	localStorage.setItem('auth_token', token);
}

const logoutBtn = document.getElementById('logoutBtn');

logoutBtn.addEventListener('click', () => {
	authFetch(`${AUTH_URL}/logout`);
});

const getUserBtn = document.getElementById('getUserBtn');
const getUserInput = document.getElementById('getUserInput');
getUserBtn.addEventListener('click', () => {
	authFetch(`${AUTH_URL}/get_user/${getUserInput.value}`).then((res) => {
		return res.json();
	}).then((res) => {
		otherUserDataEl.innerHTML = JSON.stringify(res, null, '\t');
	});
});

const myDataEl = document.getElementById('myData');
const otherUserDataEl = document.getElementById('otherUserData');

const AUTH_URL = 'https://dev12.dynamicannotationframework.com/auth';

authFetch(`${AUTH_URL}/test`).then((res) => {
	return res.json();
}).then((userData) => {
	document.body.classList.toggle('loggedIn', true);
	myDataEl.innerHTML = JSON.stringify(userData, null, '\t');
	document.body.classList.toggle('isAdmin', userData.roles.includes('admin'));
});
