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
	if (Array.isArray(input)) {
		return Promise.all(input.map((url) => {
			return authFetch(url, init, retry);
		}));
	}
	
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

		const contentType = res.headers.get("content-type");

		if (contentType === 'application/json') {
			return res.json();
		} else {
			return res;
		}
	});
}

async function reauthenticate(realm) {
	const token = await authorize(realm);
	localStorage.setItem('auth_token', token);
}

const loginBtn = document.getElementById('loginBtn');
const logoutBtn = document.getElementById('logoutBtn');

// let availableGroups = null;

// const refreshAvailableGroups = () => {
// 	return new Promise((f, r) => {
// 		authFetch(`${AUTH_URL}/group`).then((res) => {
// 			return res.json();
// 		}).then((res) => {
// 			availableGroups = res;

// 			addGroupSelect.innerHTML = "";

// 			for (let group of res) {
// 				const optionEl = document.createElement('option');
// 				optionEl.value = group.id;
// 				optionEl.innerHTML = group.name;

// 				addGroupSelect.appendChild(optionEl);
// 			}

// 			f();
// 		});
// 	})
// };

const login = () => {
	authFetch(`${AUTH_URL}/test`).then((userData) => {
		document.body.classList.toggle('loggedIn', true);
		document.body.classList.toggle('isAdmin', userData.admin);

		document.getElementById('email').innerHTML = `${userData.email}`;

		// refreshAvailableGroups();

		refreshUsers();
		refreshGroups();
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
					console.log('val', val);

					const valEL = document.createElement('div');
					valEL.innerHTML = JSON.stringify(val);

					const deleteRowEl = document.createElement('div');
					deleteRowEl.className = "deleteRow";

					el.appendChild(valEL);
					el.appendChild(deleteRowEl);

					if (el.dataset.link) {
						const funcs = {
							user: selectUser,
							group: selectGroup
						}

						if (funcs[el.dataset.link]) {
							valEL.addEventListener('click', () => {
								funcs[el.dataset.link](val.id);
							});
						}
					}

					// deleteRowEl.addEventListener('click', () => {

					// 	for (let {id, name} of availableGroups) {
					// 		if (name === val) {
					// 			authFetch(`${AUTH_URL}/group/${id}/user/${selectedUserId}`, {
					// 				method: 'DELETE'
					// 			}).then((res) => {
					// 				refreshSelectedUser();
					// 			});
					// 		}
					// 	}
					// });
				}
			} else {
				el.innerHTML = value;

				if (el.classList.contains('editable')) {
					const body = {};
					body[key] = !value;

					const newEL = () => {
						authFetch(`${AUTH_URL}/user/${selectedUserId}`, {
							method: 'PUT',
							headers: {
								'Content-Type': 'application/json'
							},
							body: JSON.stringify(body)
						}).then((res) => {
							refreshSelectedUser();
						});
					};
					
					if (el.prevEL) {
						el.removeEventListener('click', el.prevEL);
					}

					el.prevEL = newEL;
					el.addEventListener('click', newEL);
				}
			}
		}
	}
}

let selectedUserId = null;

async function refreshSelectedUser() {
	if (selectedUserId === null) {
		document.body.classList.toggle('selectedUser', false);
		return;
	}

	let [userInfo, usersGroups] = await authFetch([
		`${AUTH_URL}/user/${selectedUserId}`,
		`${AUTH_URL}/user/${selectedUserId}/groups`]
	);

	userInfo.groups = usersGroups;

	renderItem(userInfo, document.getElementById('userData'));
	document.body.classList.toggle('selectedGroup', false);
	document.body.classList.toggle('selectedUser', true);
};

let selectedGroupId = null;

async function refreshSelectedGroup() {
	if (selectedGroupId === null) {
		document.body.classList.toggle('selectedGroup', false);
		return;
	}

	let [group, users, datasets] = await authFetch([
		`${AUTH_URL}/group/${selectedGroupId}`,
		`${AUTH_URL}/group/${selectedGroupId}/user`,
		`${AUTH_URL}/group/${selectedGroupId}/dataset`
	]);

	datasets = datasets.map(([name, permissions]) => {
		return [name, {
			admin: !!(permissions & 4),
			edit: !!(permissions & 2),
			read: !!(permissions & 1)
		}];
	});

	group.users = users;
	group.datasets = datasets;

	console.log('datasets', datasets);

	renderItem(group, document.getElementById('groupData'));
	document.body.classList.toggle('selectedUser', false);
	document.body.classList.toggle('selectedGroup', true);
}

function searchList(searchBtn, url, filters, listEl, clickHandler) {
	function refresh() {
		const searchQuery = new URLSearchParams();

		for (let [key, input] of Object.entries(filters)) {
			if (input.value.length) {
				searchQuery.set(key, input.value);
			}
		}

		const searchQueryString = searchQuery.toString();
	
		authFetch(`${AUTH_URL}${url}${searchQueryString ? '?' + searchQueryString : ''}`).then((rows) => {
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
	}


	searchBtn.addEventListener('click', refresh);

	return refresh;
}

document.querySelector('#userData .closeBtn').addEventListener('click', () => {
	selectUser(null);
});

document.querySelector('#groupData .closeBtn').addEventListener('click', () => {
	selectGroup(null);
});

function selectUser(userId) {
	selectedUserId = userId;
	selectedGroupId = null;
	refreshSelectedUser();
}

function selectGroup(groupId) {
	selectedGroupId = groupId;
	selectedUserId = null;
	refreshSelectedGroup();
}

const refreshUsers = searchList(
	document.getElementById('searchUserBtn'),
	"/user",
	{
		email: document.getElementById('getUserInput')
	},
	document.getElementById('searchUserResults'),
	selectUser);

const refreshGroups = searchList(
	document.getElementById('searchGroupBtn'),
	"/group",
	{
		name: document.getElementById('getGroupInput')
	},
	document.getElementById('searchGroupResults'),
	selectGroup);

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

	authFetch(`${AUTH_URL}/group/${selectedGroupId}/dataset`, {
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
		refreshGroups();
	});
});

// createGroupInput

const myDataEl = document.getElementById('myData');

const AUTH_URL = 'https://dev.dynamicannotationframework.com/auth';

if (localStorage.getItem('auth_token')) {
	login();
}
