// returns a token to be used with services that use the given auth service
async function authorize(auth_url) {
	const oauth_uri = await fetch(`https://${auth_url}/authorize?redirect=${encodeURI(location.href.replace(/[^/]*$/, '') + 'redirect.html')}`, {
		credentials: 'include',
		headers: {
			'X-Requested-With': 'Fetch'
		}
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
		wwwAuthMap[key] = val.replace(/"/g, "");
	}

	return wwwAuthMap;
}

function authFetch(input, init, retry = 1) {
	if (!input) {
		return fetch(input); // to keep the errors consistent
	}

	const token = localStorage.getItem('auth_token');

	options = init ? JSON.parse(JSON.stringify(init)) : {};

	options.headers = options.headers || new Headers();

	function addHeader(key, value) {
		if (options.headers instanceof Headers) {
			options.headers.append(key, value);
		} else {
			options.headers[key] = value;
		}
	}

	addHeader('X-Requested-With', 'Fetch');
	
	if (token) {
		addHeader('Authorization', `Bearer ${token}`);
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

const loginBtn = document.getElementById('loginBtn');
const logoutBtn = document.getElementById('logoutBtn');

let availableGroups = null;

const refreshAvailableGroups = () => {
	return new Promise((f, r) => {
		authFetch(`${AUTH_URL}/group`).then((res) => {
			return res.json();
		}).then((res) => {
			availableGroups = res;

			addGroupSelect.innerHTML = "";

			for (let group of res) {
				const optionEl = document.createElement('option');
				optionEl.value = group.id;
				optionEl.innerHTML = group.name;

				addGroupSelect.appendChild(optionEl);
			}

			f();
		});
	})
};

const login = () => {
	authFetch(`${AUTH_URL}/test`).then((res) => {
		return res.json();
	}).then((userData) => {
		document.body.classList.toggle('loggedIn', true);
		document.body.classList.toggle('isAdmin', userData.admin);

		document.getElementById('email').innerHTML = `${userData.email} (${JSON.stringify(userData.permissions)})`;

		refreshAvailableGroups();
	});
};

loginBtn.addEventListener('click', login);

logoutBtn.addEventListener('click', () => {
	authFetch(`${AUTH_URL}/logout`).then(() => {
		localStorage.removeItem('auth_token');
		window.location.reload(false);
	});
});

function renderItem(item, containerEl) {
	for (let [key, value] of Object.entries(item)) {
		const el = containerEl.querySelector(`.${key}`);

		if (el) {
			el.innerHTML = '';

			if (el.classList.contains('list')) {
				for (let val of value) {
					const valEL = document.createElement('div');
					valEL.innerHTML = JSON.stringify(val);

					const deleteRowEl = document.createElement('div');
					deleteRowEl.className = "deleteRow";

					el.appendChild(valEL);
					el.appendChild(deleteRowEl);

					deleteRowEl.addEventListener('click', () => {

						for (let {id, name} of availableGroups) {
							if (name === val) {
								authFetch(`${AUTH_URL}/group/${id}/user/${selectedUserId}`, {
									method: 'DELETE'
								}).then((res) => {
									refreshSelectedUser();
								});
							}
						}
					});
				}
			} else {
				el.innerHTML = value;
			}
		}
	}
}

let selectedUserId = null;

const refreshSelectedUser = () => {
	if (selectedUserId === null) {
		return;
	}

	authFetch(`${AUTH_URL}/user/${selectedUserId}`).then((res) => {
		return res.json();
	}).then((res) => {
		renderItem(res, document.getElementById('otherUserData'));
		document.body.classList.toggle('selectedUser', true);
	});
};

let selectedGroupId = null;

async function refreshSelectedGroup() {
	if (selectedGroupId === null) {
		return;
	}

	let users = await authFetch(`${AUTH_URL}/group/${selectedGroupId}/users`).then((res) => {
		return res.json();
	});

	let datasets = await authFetch(`${AUTH_URL}/group/${selectedGroupId}/datasets`).then((res) => {
		return res.json();
	});


	renderItem({users: users, datasets: datasets}, document.getElementById('groupData'));
	document.body.classList.toggle('selectedGroup', true);
}

function searchList(searchBtn, searchInput, url, listEl, clickHandler) {
	searchBtn.addEventListener('click', () => {
		if (!searchInput.value.length) {
			return;
		}
	
		authFetch(`${AUTH_URL}${url}${searchInput.value}`).then((res) => {
			return res.json();
		}).then((rows) => {
			const searchResultsListEl = listEl.querySelector('.list');
			searchResultsListEl.innerHTML = "";
	
			// searchResultsListEl.classList.toggle('hasResult', true);
	
			if (rows.length === 0) {
				const rowEl = document.createElement('div');
				rowEl.innerHTML = 'No Results';
				searchResultsListEl.appendChild(rowEl);
			}
	
			for (let row of rows) {
				const rowEl = document.createElement('div');
				rowEl.innerHTML = JSON.stringify(row);
				searchResultsListEl.appendChild(rowEl);
	
				rowEl.addEventListener('click', () => {
					clickHandler(row.id);
				});
			}
		});
	});
}

searchList(
	document.getElementById('searchUserBtn'),
	document.getElementById('getUserInput'),
	"/user?email=",
	document.getElementById('searchUserResults'),
	(id) => {
		selectedUserId = id;
		refreshSelectedUser();
	});

searchList(
	document.getElementById('searchGroupBtn'),
	document.getElementById('getGroupInput'),
	"/group?name=",
	document.getElementById('searchGroupResults'),
	(id) => {
		selectedGroupId = id;
		refreshSelectedGroup();
	});

const addGroupSelect = document.getElementById('addGroupSelect');
const addGroupBtn = document.getElementById('addGroupBtn');
const removeGroupBtn = document.getElementById('removeGroupBtn');

addGroupBtn.addEventListener('click', () => {
	if (!selectedUserId) {
		return;
	}

	authFetch(`${AUTH_URL}/group/${addGroupSelect.value}/user`, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json'
		},
		body: JSON.stringify({
			user_id: Number(selectedUserId)
		})
	}).then((res) => {
		refreshSelectedUser();
	});
});

const addDatasetInput = document.getElementById('addDatasetInput');
const canViewCheckbox = document.getElementById('canViewCheckbox');
const canEditCheckbox = document.getElementById('canEditCheckbox');
const canAdminCheckbox = document.getElementById('canAdminCheckbox');
const addDatasetBtn = document.getElementById('addDatasetBtn');

addDatasetBtn.addEventListener('click', () => {
	if (!selectedGroupId) {
		return;
	}

	authFetch(`${AUTH_URL}/group/${selectedGroupId}/datasets`, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json'
		},
		body: JSON.stringify({
			dataset_name: addDatasetInput.value,
			can_view: canViewCheckbox.checked,
			can_edit: canEditCheckbox.checked,
			can_admin: canAdminCheckbox.checked
		})
	}).then((res) => {
		refreshSelectedGroup();
	});
});

const createGroupInput = document.getElementById('createGroupInput');
const createGroupBtn = document.getElementById('createGroupBtn');

createGroupBtn.addEventListener('click', () => {
	authFetch(`${AUTH_URL}/group`, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json'
		},
		body: JSON.stringify({
			name: createGroupInput.value
		})
	}).then((res) => {
		// refreshSelectedGroup();
	});
});

// createGroupInput

const myDataEl = document.getElementById('myData');

const AUTH_URL = 'https://dev.dynamicannotationframework.com/auth';

if (localStorage.getItem('auth_token')) {
	login();
}
