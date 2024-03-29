FROM openjdk:11

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

# can be passed during Docker build as build time environment for glowroot 
ARG is_glowroot

# can be passed during Docker build as build time environment for artifactory URL
ARG artifactory_url

# can be passed during Docker build as build time environment for hsm client zip file path
ARG hsm_client_zip_path

# can be passed during Docker build as build time environment management rmi server hostname
#ARG management_rmi_server_hostname

# can be passed during Docker build as build time environment management rmi server port
#ARG management_jmxremote_rmi_port

# environment variable to pass active profile such as DEV, QA etc at docker runtime
ENV active_profile_env=${active_profile}

# environment variable to pass github branch to pickup configuration from, at docker runtime
ENV spring_config_label_env=${spring_config_label}

# environment variable to pass spring configuration url, at docker runtime
ENV spring_config_url_env=${spring_config_url}

# environment variable to pass glowroot, at docker runtime
ENV is_glowroot_env=${is_glowroot}

# environment variable to pass artifactory url, at docker runtime
ENV artifactory_url_env=${artifactory_url}
# environment variable to pass iam_adapter url, at docker runtime
ENV iam_adapter_url_env=${iam_adapter_url}

# environment variable to pass hsm client zip file path, at docker runtime
ENV hsm_zip_file_path=${hsm_client_zip_path}

# environment variable to pass management rmi server hostname, at docker runtime
#ENV management_rmi_server_hostname_env=${management_rmi_server_hostname}

# environment variable to pass management rmi server port, at docker runtime
#ENV management_jmxremote_rmi_port_env=${management_jmxremote_rmi_port}

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

# install packages and create user
RUN apt-get -y update \
&& apt-get install -y unzip sudo\
&& groupadd -g ${container_user_gid} ${container_user_group} \
&& useradd -u ${container_user_uid} -g ${container_user_group} -s /bin/sh -m ${container_user} \
&& adduser ${container_user} sudo \
&& echo "%sudo ALL=(ALL) NOPASSWD:/home/${container_user}/${hsm_local_dir}/install.sh" >> /etc/sudoers

# set working directory for the user
WORKDIR /home/${container_user}

ENV work_dir=/home/${container_user}

ARG loader_path=${work_dir}/additional_jars/

RUN mkdir -p ${loader_path}

ENV loader_path_env=${loader_path}

ADD configure_start.sh configure_start.sh

ADD ./lib/* "${loader_path_env}"/

RUN chmod +x configure_start.sh

# creating folder to copy additional supporting jar files required at run-time.
#RUN mkdir -p /home/${container_user}/additional-jars

ADD ./target/*.jar /target/
RUN find /target -name '*.jar' -executable -type f "-print0" | xargs "-0" cp -t / \
    && rm -rf /target \
    && mv /*.jar ${work_dir}/kernel-keymanager-service.jar

# change permissions of file inside working dir
RUN chown -R ${container_user}:${container_user} /home/${container_user}

# select container user for all tasks
USER ${container_user_uid}:${container_user_gid}

EXPOSE 8088
EXPOSE 9010

ENTRYPOINT [ "./configure_start.sh" ]
CMD if [ "$is_glowroot_env" = "present" ]; then \
    wget -q "${artifactory_url_env}"/artifactory/libs-release-local/io/mosip/testing/glowroot.zip ; \
    unzip glowroot.zip ; \
    rm -rf glowroot.zip ; \
    sed -i 's/<service_name>/kernel-keymanager-service/g' glowroot/glowroot.properties ; \
    wget -q "${iam_adapter_url_env}" -O "${loader_path_env}"/kernel-auth-adapter.jar; \
    java -jar -javaagent:glowroot/glowroot.jar -Dloader.path="${loader_path_env}" -Dspring.cloud.config.label="${spring_config_label_env}" -Dspring.profiles.active="${active_profile_env}" -Dspring.cloud.config.uri="${spring_config_url_env}" -XX:HeapDumpPath=/home/  ./kernel-keymanager-service.jar ; \
    else \
    wget -q "${iam_adapter_url_env}" -O "${loader_path_env}"/kernel-auth-adapter.jar; \
    java -jar -Dloader.path="${loader_path_env}" -Dspring.cloud.config.label="${spring_config_label_env}" -Dspring.profiles.active="${active_profile_env}" -Dspring.cloud.config.uri="${spring_config_url_env}" ./kernel-keymanager-service.jar ; \
    fi

