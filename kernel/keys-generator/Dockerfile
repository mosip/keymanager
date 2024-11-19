FROM eclipse-temurin:21-jre

ARG SOURCE
ARG COMMIT_HASH
ARG COMMIT_ID
ARG BUILD_TIME
LABEL source=${SOURCE}
LABEL commit_hash=${COMMIT_HASH}
LABEL commit_id=${COMMIT_ID}
LABEL build_time=${BUILD_TIME}

# can be passed during Docker build as build time environment for github branch to pickup configuration from.
ARG spring_config_label

# can be passed during Docker build as build time environment for spring profiles active 
ARG active_profile

# can be passed during Docker build as build time environment for config server URL 
ARG spring_config_url

# can be passed during Docker build as build time environment for artifactory URL
ARG artifactory_url

# can be passed during Docker build as build time environment for config server URL 
ARG spring_config_name

# can be passed during Docker build as build time environment for hsm client zip file path
ARG hsm_client_zip_path

ARG hsm_local_dir=hsm-client

ENV hsm_local_dir_name=${hsm_local_dir}

# environment variable to pass active profile such as DEV, QA etc at docker runtime
ENV active_profile_env=${active_profile}

# environment variable to pass github branch to pickup configuration from, at docker runtime
ENV spring_config_label_env=${spring_config_label}

# environment variable to pass spring configuration url, at docker runtime
ENV spring_config_url_env=${spring_config_url}

# environment variable to pass github branch to pickup configuration from, at docker runtime
ENV spring_config_name_env=${spring_config_name}

# environment variable to pass artifactory url, at docker runtime
ENV artifactory_url_env=${artifactory_url}

# environment variable to pass hsm client zip file path, at docker runtime
ENV hsm_zip_file_path=${hsm_client_zip_path}

# creating folder to copy additional supporting jar files required at run-time.
#RUN mkdir /additional-jars

# can be passed during Docker build as build time environment for github branch to pickup configuration from.
ARG container_user=mosip

# can be passed during Docker build as build time environment for github branch to pickup configuration from.
ARG container_user_group=mosip

# can be passed during Docker build as build time environment for github branch to pickup configuration from.
ARG container_user_uid=1001

# can be passed during Docker build as build time environment for github branch to pickup configuration from.
ARG container_user_gid=1001

ARG hsm_local_dir=hsm-client

ENV hsm_local_dir_name=${hsm_local_dir}

# set working directory for the user
WORKDIR /home/${container_user}

ENV work_dir=/home/${container_user}

ARG loader_path=${work_dir}/additional_jars/

ENV loader_path_env=${loader_path}

ADD configure_start.sh configure_start.sh

ADD target/keys-generator-*.jar keys-generator.jar

# install packages and create user
RUN apt-get -y update \
&& apt-get install -y unzip sudo adduser \
&& groupadd -g ${container_user_gid} ${container_user_group} \
&& useradd -u ${container_user_uid} -g ${container_user_group} -s /bin/bash -m ${container_user} \
&& adduser ${container_user} sudo \
&& echo "%sudo ALL=(ALL) NOPASSWD:/home/${container_user}/${hsm_local_dir}/install.sh" >> /etc/sudoers \
&& mkdir -p ${loader_path} \
&& chmod +x configure_start.sh

ENTRYPOINT [ "./configure_start.sh" ]

CMD ["java","-jar", "-Dloader.path=${loader_path_env}", "-Dspring.cloud.config.label=${spring_config_label_env}","-Dspring.cloud.config.name=${spring_config_name_env}", "-Dspring.profiles.active=${active_profile_env}", "-Dspring.cloud.config.uri=${spring_config_url_env}", "./keys-generator.jar"]
