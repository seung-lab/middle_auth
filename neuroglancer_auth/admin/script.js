const AUTH_URL = 'https://fafbm.dynamicannotationframework.com/auth';

const datasetDataApp = {
	data: () => ({
		loading: true,
		newEntry: false,
		dataset: null,
		errors: []
	}),
	mounted: async function () {
		if (this.$route.params.id === 'create') {
			this.newEntry = true;
			this.loading = false;

			this.dataset = {
				name: ''
			};

			return;
		}

		const id = Number.parseInt(this.$route.params.id);
	},
	methods: {
		save() {
			this.errors = [];

			if (this.newEntry) {
				console.log('save new entry!');

				if (!this.dataset.name) {
					this.errors.push(['name', 'missing']);
				}

				if (!this.errors.length) {
					authFetch(`${AUTH_URL}/dataset`, {
						method: 'POST',
						headers: {
							'Content-Type': 'application/json'
						},
						body: JSON.stringify({
							name: this.dataset.name
						})
					}).then((res) => {
						console.log('updated entry!');
						router.push('./')
					})
					.catch((res) => {
						alert(res);
					})
				}
			} else {
				console.log('update entry!');
			}
		}
	},
	template: `
	<div>
	<template v-if="loading">Loading...</template>
	<template v-else>
		<div id="userData">
			<div class="title" v-if="newEntry">Create Dataset</div>
			<div class="title" v-else>Edit Dataset</div>

			<input v-model="dataset.name" placeholder="Name" required>

			<button @click="save" v-if="newEntry">Create</button>
			<button @click="save" v-else>Update</button>
		</div>
	</template>
	</div>
	`
};

const groupDataApp = {
	data: () => ({
		loading: true,
		newEntry: false,
		group: null,
		users: [],
		datasets: [],
		availableDatasets: [],
		allDatasets: [],
		selectedDataset: '',
		canAdmin: false,
		canEdit: false,
		canView: false
	}),
	mounted: async function () {
		if (this.$route.params.id === 'create') {
			this.newEntry = true;
			this.loading = false;

			this.group = {
				name: ''
			};

			return;
		}

		const id = Number.parseInt(this.$route.params.id);

		let [group, users, datasets, availableDatasets] = await authFetch([
			`${AUTH_URL}/group/${id}`,
			`${AUTH_URL}/group/${id}/user`,
			`${AUTH_URL}/group/${id}/dataset`,
			`${AUTH_URL}/dataset`
		]);
	
		this.group = group;
	
		this.users = users;
		this.datasets = datasets;

		this.allDatasets = availableDatasets;
		this.updateAvailableDatasets();

		this.loading = false;
	},
	methods: {
		updateAvailableDatasets() {
			this.availableDatasets = this.allDatasets.filter((dataset) => {
				return !this.datasets.map((d) => d.id).includes(dataset.id);
			});
		},
		async addDataset() {
			await authFetch(`${AUTH_URL}/group/${this.group.id}/dataset`, {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json'
				},
				body: JSON.stringify({
					dataset_id: this.selectedDataset,
					view: this.canView,
					edit: this.canEdit,
					admin: this.canAdmin
				})
			});

			this.datasets = await authFetch(`${AUTH_URL}/group/${this.group.id}/dataset`);
			this.updateAvailableDatasets();
		},
		async updatePermissions(dataset) {
			await authFetch(`${AUTH_URL}/group/${this.group.id}/dataset/${dataset.id}`, {
				method: 'PUT',
				headers: {
					'Content-Type': 'application/json'
				},
				body: JSON.stringify(dataset.permissions)
			});

			// not necessary but good to make sure that it registered
			this.datasets = await authFetch(`${AUTH_URL}/group/${this.group.id}/dataset`);
			this.updateAvailableDatasets();
		},
		async removeDataset(dataset_id) {
			await authFetch(`${AUTH_URL}/group/${this.group.id}/dataset/${dataset_id}`, {
				method: 'DELETE'
			});

			this.datasets = await authFetch(`${AUTH_URL}/group/${this.group.id}/dataset`);
			this.updateAvailableDatasets();
		},
		async save() {
			this.errors = [];

			if (this.newEntry) {
				console.log('save new entry!');

				if (!this.group.name) {
					this.errors.push(['name', 'missing']);
				}

				if (!this.errors.length) {
					authFetch(`${AUTH_URL}/group`, {
						method: 'POST',
						headers: {
							'Content-Type': 'application/json'
						},
						body: JSON.stringify({
							name: this.group.name
						})
					}).then((res) => {
						console.log('updated entry!');
						router.push('./')
					})
					.catch((res) => {
						alert(res);
					})
				}
			} else {
				console.log('update entry!');
			}
		}
	},
	template: `
	<div>
	<template v-if="loading">Loading...</template>
	<template v-else-if="newEntry">
		<div id="userData">
			<div class="title" v-if="newEntry">Create Group</div>
			<div class="title" v-else>Edit Group</div>

			<input v-model="group.name" placeholder="Name" required>

			<button @click="save" v-if="newEntry">Create</button>
			<button @click="save" v-else>Update</button>
		</div>
	</template>
	<template v-else>
		<div id="groupData">
			<div class="title">Edit Group</div>
			<div class="name">{{ group.name }}</div>

			<div class="listContainer">
				<div class="header">Users</div>
				<div class="users list" data-link="user">
					<div v-for="user in users">
						<router-link :to="{ name: 'userData', params: { id: user.id }}">
							{{ user.name }}
						</router-link>
						<div class="deleteRow" @click="removeUser(user.id)"></div>
					</div>
				</div>
			</div>

			<div class="listContainer">
				<div class="header"><span>Datasets</span></div>
				<div class="datasets list" data-link="dataset">
					<div v-for="dataset in datasets">
						<div>{{ dataset.name }}</div>
						<template v-for="(pon, pname) in dataset.permissions">
							<div class="datasetPermissionToggle">
								<label :for="dataset.name + '_' + pname">{{ pname }}</label>
								<input :id="dataset.name + '_' + pname" type="checkbox" v-model="dataset.permissions[pname]" @change="updatePermissions(dataset)">
							</div>
						</template>
						<div class="deleteRow" @click="removeDataset(dataset.id)"></div>
					</div>
				</div>
			</div>

			<div>
				<select v-model="selectedDataset">
					<option disabled="disabled" value="">Select Dataset</option>
					<option v-for="dataset in availableDatasets" v-bind:value="dataset.id">{{ dataset.name }}</option>
				</select>
				<div>
					<input type="checkbox" id="canAdmin" v-model="canAdmin">
					<label for="canAdmin">Admin</label>
					<input type="checkbox" id="canEdit" v-model="canEdit">
					<label for="canEdit">Edit</label>
					<input type="checkbox" id="canView" v-model="canView">
					<label for="canView">View</label>
				</div>
				<button @click="addDataset">Add Dataset</button>
			</div>
		</div>
	</template>
	</div>
	`
};

const userDataApp = {
	data: () => ({
		loading: true,
		user: null,
		groups: [],
		availableGroups: [],
		allGroups: [],
		selectedGroup: ''
	}),
	mounted: async function () {
		console.log('mounted!');

		const id = Number.parseInt(this.$route.params.id);

		let [userInfo, usersGroups, groups] = await authFetch([
			`${AUTH_URL}/user/${id}`,
			`${AUTH_URL}/user/${id}/groups`,
			`${AUTH_URL}/group`]
		);
	
		this.user = userInfo;
		this.groups = usersGroups;
		this.allGroups = groups;

		this.updateAvailableGroups();

		this.loading = false;
	},
	methods: {
		updateAvailableGroups() {
			this.availableGroups = this.allGroups.filter((group) => {
				return !this.groups.map((g) => g.id).includes(group.id);
			});
		},
		async joinGroup() {
			await authFetch(`${AUTH_URL}/group/${this.selectedGroup}/user`, {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json'
				},
				body: JSON.stringify({
					user_id: this.user.id
				})
			});

			this.groups = await authFetch(`${AUTH_URL}/user/${this.user.id}/groups`);
			this.updateAvailableGroups();
		},
		async leaveGroup(groupId) {
			await authFetch(`${AUTH_URL}/group/${groupId}/user/${this.user.id}`, {
				method: 'DELETE'
			});

			this.groups = await authFetch(`${AUTH_URL}/user/${this.user.id}/groups`);
			this.updateAvailableGroups();
		}
	},
	template: `
	<div>
	<template v-if="loading">Loading...</template>
	<template v-else>
		<div id="userData">
			<div class="title">Edit User</div>
			<div class="name">{{ user.name }}</div>
			<div class="email">{{ user.email }}</div>
			<div class="admin editable">{{ user.admin }}</div>

			<div class="listContainer">
				<div class="header">Groups</div>
				<div class="groups list" data-link="group">
					<div v-for="group in groups">
						<router-link :to="{ name: 'groupData', params: { id: group.id }}">
							{{ group.name }}
						</router-link>
						<div class="deleteRow" @click="leaveGroup(group.id)"></div>
					</div>
				</div>
			</div>

			<div>
				<select v-model="selectedGroup">
					<option disabled="disabled" value="">Select Group</option>
					<option v-for="group in availableGroups" v-bind:value="group.id">{{ group.name }}</option>
				</select>
				<button @click="joinGroup">Join Group</button>
			</div>
		</div>
	</template>
	</div>
	`
};

const listApp = {
	data: () => ({
		loading: true,
		rows: [],
		searchInput: '',
		url: '',
		searchKey: '',
		title: '',
		displayedProps: ['id'],
		canCreate: false
	}),
	methods: {
		refresh() {
			const searchQuery = new URLSearchParams();

			if (this.searchInput.length) {
				searchQuery.set(this.searchKey, this.searchInput);
			}

			const searchQueryString = searchQuery.toString();
		
			authFetch(`${AUTH_URL}${this.url}${searchQueryString ? '?' + searchQueryString : ''}`).then((rows) => {
				this.rows = rows;
				this.loading = false;
			});
		}
	},
	mounted: function () {
		this.refresh();
	},
	template: `
	<div id="searchUsers" class="searchAndResults">
	<div class="searchForm right">
		<input v-model="searchInput" @keyup.enter="refresh" type="email" :placeholder="searchKey">
	</div>

	<div id="searchUserResults" class="listContainer block">
		<div class="header">{{ title }}</div>
		<div class="list selectable" :style="{'grid-template-columns': 'repeat(' + displayedProps.length + ', auto)' }">
			<div v-if="loading">
				<div>Loading...</div>
			</div>
			<div v-else-if="rows.length === 0">
				<div>No Results</div>
			</div>
			<template v-else>
				<router-link v-for="data in rows" v-bind:key="data.id" :to="{ path: '' + data.id }" append>
					<div v-for="prop in displayedProps">{{ data[prop] }}</div>
				</router-link>
			</template>
		</div>
	</div>


	<router-link v-if="canCreate" :to="{ path: 'create' }" append>Create</router-link>

	</div>
	`
}

const userListApp = {
	mixins: [listApp],
	data: () => ({
		url: '/user',
		searchKey: 'email',
		title: 'Users',
		displayedProps: ['name', 'email']
	})
};

const groupListApp = {
	mixins: [listApp],
	data: () => ({
		url: '/group',
		searchKey: 'name',
		title: 'Groups',
		displayedProps: ['name'],
		canCreate: true
	})
};

const datasetListApp = {
	mixins: [listApp],
	data: () => ({
		url: '/dataset',
		searchKey: 'name',
		title: 'Datasets',
		displayedProps: ['name'],
		canCreate: true
	})
};

const routes = [
	{ path: '/user', name: 'userList', component: userListApp },
	{ path: '/user/:id', name: 'userData', component: userDataApp },
	{ path: '/group', name: 'groupList', component: groupListApp },
	{ path: '/group/:id', name: 'groupData', component: groupDataApp },
	{ path: '/dataset', name: 'datasetList', component: datasetListApp },
	{ path: '/dataset/:id', name: 'datasetData', component: datasetDataApp },
];

const router = new VueRouter({
	routes
});

const mainApp = new Vue({
	el: "#vueApp",
	router: router,
	data: {
		loggedInUser: null
	},
	methods: {
		login() {
			authFetch(`${AUTH_URL}/test`).then((userData) => {
				this.loggedInUser = userData;
			});
		},
		logout() {
			authFetch(`${AUTH_URL}/logout`).then(() => {
				this.loggedInUser = null;
				localStorage.removeItem('auth_token');
				// window.location.reload(false);
			});
		}
	}
});


// returns a token to be used with services that use the given auth service
async function authorize(auth_url) {
	const plainURL = `${location.origin}${location.pathname}`.replace(/[^/]*$/, '');

	const oauth_uri = await fetch(`https://${auth_url}/authorize?redirect=${encodeURI(plainURL + 'redirect.html')}`, {
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

async function authFetch(input, init, retry = 1) {
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

	let res = await fetch(input, options);

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
		const json = await res.json();

		if (res.status === 200) {
			return json;
		} else {
			throw new Error(`status: ${res.status} message: ${json}`);
		}
	} else {
		if (res.status === 200) {
			return res;
		} else {
			throw new Error(`status: ${res.status}`);
		}
	}
}

async function reauthenticate(realm) {
	const token = await authorize(realm);
	localStorage.setItem('auth_token', token);
}

if (localStorage.getItem('auth_token')) {
	mainApp.login();
}
