FROM openjdk:11

ARG SOURCE
ARG COMMIT_HASH
ARG COMMIT_ID
ARG BUILD_TIME
LABEL source=${SOURCE}
LABEL commit_hash=${COMMIT_HASH}
LABEL commit_id=${COMMIT_ID}
LABEL build_time=${BUILD_TIME}

# can be passed during Docker build as build time environment for github branch to pickup configuration from | spring profiles active | config server URL | artifactory URL | config server URL and hsm client zip file path respectively.
ARG spring_config_label  
ARG active_profile 
ARG spring_config_url
ARG artifactory_url 
ARG spring_config_name
ARG hsm_client_zip_path
ARG hsm_local_dir=hsm-client

ENV hsm_local_dir_name=${hsm_local_dir}

# environment variable to pass active profile such as DEV, QA etc at docker runtime | github branch to pickup configuration from, at docker runtime | spring configuration url, at docker runtime | github branch to pickup configuration from, at docker runtime | artifactory url, at docker runtime and hsm client zip file path, at docker runtime respectively.
ENV active_profile_env=${active_profile}
ENV spring_config_label_env=${spring_config_label}
ENV spring_config_url_env=${spring_config_url}
ENV spring_config_name_env=${spring_config_name}
ENV artifactory_url_env=${artifactory_url}
ENV hsm_zip_file_path=${hsm_client_zip_path}

# can be passed during Docker build as build time environment for github branch to pickup configuration from.
ARG container_user=mosip
ARG container_user_group=mosip
ARG container_user_uid=1001
ARG container_user_gid=1001

# creating folder to copy additional supporting jar files required at run-time.
#RUN mkdir /additional-jars

WORKDIR /home/${container_user}

ENV work_dir=/

ARG loader_path=${work_dir}/additional_jars/

ENV loader_path_env=${loader_path}

ADD configure_start.sh configure_start.sh

ADD target/keys-migrator-*.jar keys-migrator.jar

# Creating the user and group
RUN groupadd -r ${container_user_group} --gid ${container_user_gid} \
    && useradd -r -g ${container_user_group} --uid ${container_user_uid} ${container_user} \
    && apt-get update \
    && apt-get -y upgrade \
    && apt-get -y install unzip \
    && mkdir -p ${loader_path} \
    && chmod +x configure_start.sh \
    && chown -R ${container_user}:${container_user} /home/${container_user}

USER ${container_user_uid}:${container_user_gid}

ENTRYPOINT [ "/configure_start.sh" ]

CMD ["java","-jar", "-Dloader.path=${loader_path_env}", "-Dspring.cloud.config.label=${spring_config_label_env}","-Dspring.cloud.config.name=${spring_config_name_env}", "-Dspring.profiles.active=${active_profile_env}", "-Dspring.cloud.config.uri=${spring_config_url_env}", "/keys-migrator.jar"]
