# PoV Manager

PoV Manager is the tool used by the PoV Specialists to manage PoVs.

For detailed information, user documentation or techincal documentation, please visit [PoV Manager documentation](https://secureworks.atlassian.net/wiki/spaces/LS/pages/468895663237/PoV+Manager).

## How to Install Locally

### Requirements
- **Docker**
- **Access to internet to pull required public docker images**

### Installation Steps
1. **Clone the Repository**  
   ```bash
   git clone https://code.8labs.io/project/presales/pov-manager.git
   cd pov-manager
   ```

2. **Update docker-compose file**

   - **Add credentials for PostgreSQL**
   - **Add credentials for MongoDB.**

3. **Create an .env File**

- **In the root of the repository, create a file named .env to store your environment variables.**
- **Please use blank.env file to understand what environment variables need to be addressed.**
- **Add your PostgreSQL database credentials in the following format:**

   ```bash
   POSTGRES_URL=postgres://<user>:<password>@127.0.0.1:<port>/<database-name>
   ```

4. **Set default credentials for PostgreSQL and MondogDB**

- **Set the credentials written in docker-compose file in db/init/init.sql file and mongo_db/init-mongo.js file**

5. **Run PoV Manager**
   - **Use the following command to run the application:**

   ```bash
   docker compose up --build -d
   ```

6. **Run migrations**
- **Use the following command to apply database migrations:**

   ```bash
   python pov_manager/manage.py migrate
   ```

7. **Provisioning setup**
- **In order to have all the necessary data running inside local environment run the following command:**

   ```bash
   python pov_manager/manage.py provisioning_setup
   ```

8. **Create super user**
   ```bash
   python pov_manager/manage.py createsuperuser
   ```
   
9. **Test running app**
- **Open browser and access localhost:8000 to check if you app is up and running**

Your PV Manager is now set up and running locally!
