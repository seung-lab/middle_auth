const AUTH_URL = 'https://fafbm.dynamicannotationframework.com/auth';

const datasetDataApp = {
	data: () => ({
		loading: true,
		newEntry: false,
		dataset: null,
		errors: [],
		groups: [],
		admins: [],
		allGroups: [],
		availableGroups: [],
		selectedGroup: '',
		selectedLevel: '',
		availableLevels: ['none', 'view', 'edit'],
		newAdmin: ''
	}),
	async beforeRouteUpdate (to, from, next) {
		await this.load(to.params.id);
		next();
	},
	mounted: async function () {
		await this.load(this.$route.params.id);
	},
	methods: {
		async load(param_id) {
			this.loading = true;

			this.newEntry = param_id === 'create';

			if (this.newEntry) {
				this.loading = false;

				this.dataset = {
					name: ''
				};

				return;
			}

			const id = Number.parseInt(param_id);

			this.dataset = await authFetch(`${AUTH_URL}/dataset/${id}`);
			this.allGroups = await authFetch(`${AUTH_URL}/group`);
			this.admins = await authFetch(`${AUTH_URL}/dataset/${id}/admin`);
			await this.updateAvailableGroups();

			this.loading = false;
		},
		async updateAvailableGroups() {
			this.groups = await authFetch(`${AUTH_URL}/dataset/${this.dataset.id}/group`);

			this.availableGroups = this.allGroups.filter((group) => {
				return !this.groups.map((g) => g.id).includes(group.id);
			});
		},
		async addGroupDataset() {
			await authFetch(`${AUTH_URL}/dataset/${this.dataset.id}/group`, {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json'
				},
				body: JSON.stringify({
					group_id: this.selectedGroup,
					level: Number.parseInt(this.selectedLevel)
				})
			});
		
			await this.updateAvailableGroups();
		},
		async removeGroup(group) {
			await authFetch(`${AUTH_URL}/dataset/${this.dataset.id}/group/${group.id}`, {
				method: 'DELETE'
			});

			await this.updateAvailableGroups();
		},
		async updatePermissions(group) {
			await authFetch(`${AUTH_URL}/dataset/${this.dataset.id}/group/${group.id}`, {
				method: 'PUT',
				headers: {
					'Content-Type': 'application/json'
				},
				body: JSON.stringify({
					level: group.level
				})
			});

			await this.updateAvailableGroups();
		},
		save() {
			this.errors = [];

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
					router.push({ name: 'datasetData', params: { id: res.id }});
				})
				.catch((res) => {
					alert(res);
				});
			}
		},
		async addAdmin() {
			const searchQuery = new URLSearchParams();
			searchQuery.set('name', this.newAdmin);
			const searchQueryString = searchQuery.toString();
			
			const users = await authFetch(`${AUTH_URL}/user?${searchQueryString}`);

			if (users) {
				const user = users[0];

				await authFetch(`${AUTH_URL}/dataset/${this.dataset.id}/admin`, {
					method: 'POST',
					headers: {
						'Content-Type': 'application/json'
					},
					body: JSON.stringify({
						dataset_id: this.dataset.id,
						user_id: user.id
					})
				});

				this.admins = await authFetch(`${AUTH_URL}/dataset/${this.dataset.id}/admin`);
			} else {
				alert('user not found!');
			}
		},
		async removeAdmin(admin) {
			await authFetch(`${AUTH_URL}/dataset/${this.dataset.id}/admin/${admin.id}`, {
				method: 'DELETE'
			});

			this.admins = await authFetch(`${AUTH_URL}/dataset/${this.dataset.id}/admin`);
		}
	},
	template: `
	<div>
	<template v-if="loading">Loading...</template>
	<template v-else>
		<div id="datasetData">
			<div class="title" v-if="newEntry">Create Dataset</div>
			<div class="title" v-else>Edit Dataset</div>

			<template v-if="newEntry">
				<input v-model="dataset.name" placeholder="Name" required>
			</template>
			<template v-else>
				<div>{{ dataset.name }}</div>
			</template>

			<template v-if="!newEntry">
				<div class="listContainer">
					<div class="header"><span>Groups</span></div>
					<div class="permissions list">
						<div v-for="group in groups">
							<router-link :to="{ name: 'groupData', params: { id: group.id }}">
								{{ group.name }}
							</router-link>
							<div>
								<select @change="updatePermissions(group)" v-model="group.level">
									<option v-for="(item, index) in availableLevels" v-bind:value="index">{{ item }}</option>
								</select>
							</div>
							<div class="deleteRow" @click="removeGroup(group)"></div>
						</div>
					</div>
				</div>

				<div>
					<select v-model="selectedGroup">
						<option disabled="disabled" value="">Select Group</option>
						<option v-for="group in availableGroups" v-bind:value="group.id">{{ group.name }}</option>
					</select>
					<select v-model="selectedLevel">
						<option disabled="disabled" value="">Select Level</option>
						<option value="1">View</option>
						<option value="2">Edit</option>
					</select>
					<button @click="addGroupDataset">Add Group</button>
				</div>

				<div v-if="!loading" class="listContainer">
					<div class="header"><span>Admins</span></div>
					<div class="admins list">
						<div v-for="admin in admins">
							<router-link :to="{ name: 'userData', params: { id: admin.id }}">
								{{ admin.name }}
							</router-link>
							<div class="deleteRow" @click="removeAdmin(admin)"></div>
						</div>
					</div>
				</div>

				<div>
					<input v-model="newAdmin" placeholder="Name">
					<button @click="addAdmin">Add Admin</button>
				</div>
			</template>
			<button @click="save" v-if="newEntry">Create</button>
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
		admins: [],
		nonAdmins: [],
		datasets: [],
		availableDatasets: [],
		allDatasets: [],
		selectedUser: '',
		selectedDataset: '',
		selectedLevel: '',
		availableLevels: ['none', 'view', 'edit']
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
		this.admins = await authFetch(`${AUTH_URL}/group/${id}/admin`);
		this.updateNonAdmins();
		this.datasets = datasets;

		this.allDatasets = availableDatasets;
		this.updateAvailableDatasets();

		this.loading = false;
	},
	methods: {
		async removeUser(userId) {
			await authFetch(`${AUTH_URL}/group/${this.group.id}/user/${userId}`, {
				method: 'DELETE'
			});

			this.users = await authFetch(`${AUTH_URL}/group/${this.group.id}/user`);
			this.admins = await authFetch(`${AUTH_URL}/group/${this.group.id}/admin`);
			this.updateNonAdmins();
		},
		async makeAdmin() {
			this.setAdmin(parseInt(this.selectedUser), true);
		},
		async setAdmin(userId, admin) {
			await authFetch(`${AUTH_URL}/group/${this.group.id}/user/${userId}`, {
				method: 'PUT',
				headers: {
					'Content-Type': 'application/json'
				},
				body: JSON.stringify({
					admin: admin
				})
			});

			this.users = await authFetch(`${AUTH_URL}/group/${this.group.id}/user`);
			this.admins = await authFetch(`${AUTH_URL}/group/${this.group.id}/admin`);
			this.updateNonAdmins();
		},
		async addGroupDataset() {
			await authFetch(`${AUTH_URL}/dataset/${this.selectedDataset}/group`, {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json'
				},
				body: JSON.stringify({
					group_id: this.group.id,
					level: Number.parseInt(this.selectedLevel)
				})
			});
		
			this.datasets = await authFetch(`${AUTH_URL}/group/${this.group.id}/dataset`);
			this.updateAvailableDatasets();
		},
		updateAvailableDatasets() {
			this.availableDatasets = this.allDatasets.filter((dataset) => {
				return !this.datasets.map((d) => d.id).includes(dataset.id);
			});
		},
		updateNonAdmins() {
			this.nonAdmins = this.users.filter((user) => {
				return !this.admins.map((u) => u.id).includes(user.id);
			});
		},
		async updatePermissions(dataset) {
			await authFetch(`${AUTH_URL}/dataset/${dataset.id}/group/${this.group.id}`, {
				method: 'PUT',
				headers: {
					'Content-Type': 'application/json'
				},
				body: JSON.stringify({
					level: dataset.level
				})
			});

			// not necessary but good to make sure that it registered
			this.datasets = await authFetch(`${AUTH_URL}/group/${this.group.id}/dataset`);
			this.updateAvailableDatasets();
		},
		async removeDataset(dataset_id) {
			await authFetch(`${AUTH_URL}/dataset/${dataset_id}/group/${this.group.id}`, {
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

			<button @click="save">Create</button>
		</div>
	</template>
	<template v-else>
		<div id="groupData">
			<div class="title">Edit Group</div>
			<div class="name">{{ group.name }}</div>

			<div class="listContainer">
				<div class="header">Admins</div>
				<div class="admins list">
					<div v-for="user in admins">
						<div>
							<router-link :to="{ name: 'userData', params: { id: user.id }}">
								{{ user.name }}
							</router-link>
						</div>
						<div class="deleteRow" @click="setAdmin(user.id, false)"></div>
					</div>
				</div>
			</div>

			<div class="listContainer">
				<div class="header"><span>Datasets</span></div>
				<div class="permissions list">
					<div v-for="dataset in datasets">
						<router-link :to="{ name: 'datasetData', params: { id: dataset.id }}">
							{{ dataset.name }}
						</router-link>
						<div>
							<select @change="updatePermissions(dataset)" v-model="dataset.level">
								<option v-for="(item, index) in availableLevels" v-bind:value="index">{{ item }}</option>
							</select>
						</div>
						<div class="deleteRow" @click="removeDataset(dataset.id)"></div>
					</div>
				</div>
			</div>

			<div>
				<select v-model="selectedUser">
					<option disabled="disabled" value="">Select User</option>
					<option v-for="user in nonAdmins" v-bind:value="user.id">{{ user.name }} ({{ user.email }})</option>
				</select>
				<button @click="makeAdmin">Make Admin</button>
			</div>

			<div>
				<select v-model="selectedDataset">
					<option disabled="disabled" value="">Select Dataset</option>
					<option v-for="dataset in availableDatasets" v-bind:value="dataset.id">{{ dataset.name }}</option>
				</select>
				<select v-model="selectedLevel">
					<option disabled="disabled" value="">Select Level</option>
					<option value="1">View</option>
					<option value="2">Edit</option>
				</select>
				<button @click="addGroupDataset">Add Dataset</button>
			</div>

			<div class="listContainer">
				<div class="header">Users</div>
				<div class="users list">
					<div v-for="user in users">
						<div>
							<router-link :to="{ name: 'userData', params: { id: user.id }}">
								{{ user.name }}
							</router-link>
							<span class="is_admin" v-if="user.admin">Admin</span>
						</div>
						<div class="deleteRow" @click="removeUser(user.id)"></div>
					</div>
				</div>
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
			`${AUTH_URL}/user/${id}/group`,
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
		async update() {
			await authFetch(`${AUTH_URL}/user/${this.user.id}`, {
				method: 'PUT',
				headers: {
					'Content-Type': 'application/json'
				},
				body: JSON.stringify({
					admin: !this.user.admin
				})
			});

			this.user = await authFetch(`${AUTH_URL}/user/${this.user.id}`);
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

			this.groups = await authFetch(`${AUTH_URL}/user/${this.user.id}/group`);
			this.updateAvailableGroups();
		},
		async leaveGroup(groupId) {
			await authFetch(`${AUTH_URL}/group/${groupId}/user/${this.user.id}`, {
				method: 'DELETE'
			});

			this.groups = await authFetch(`${AUTH_URL}/user/${this.user.id}/group`);
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
			<div @click="update" class="admin editable">{{ user.admin }}</div>

			<div class="listContainer">
				<div class="header">Groups</div>
				<div class="groups list">
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
		loggedInUser: null,
		networkResponse: null
	},
	watch: {
		networkResponse: function (newMessage) {
			if (newMessage) {
				setTimeout(() => {
					this.networkResponse = null;
				}, 400 + 500);
			}
		}
	},
	methods: {
		login() {
			authFetch(`${AUTH_URL}/user/me`).then((userData) => {
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

	const httpMethod = (init && init.method) || 'GET';


	const contentType = res.headers.get("content-type");

	const message = await ((contentType === 'application/json') ? res.json() : res.text());


	if (httpMethod !== 'GET') {
		mainApp.networkResponse = {
			message: res.status === 200 ? 'Success!' : message,
			error: res.status !== 200
		};
	}

	if (res.status === 200) {
		return message;
	} else {
		throw new Error(`status: ${res.status} message: ${message}`);
	}
}

async function reauthenticate(realm) {
	const token = await authorize(realm);
	localStorage.setItem('auth_token', token);
}

if (localStorage.getItem('auth_token')) {
	mainApp.login();
}
