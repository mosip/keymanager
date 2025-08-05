package io.mosip.kernel.keymanagerservice.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import io.mosip.kernel.keymanagerservice.entity.KeyAlias;

/**
 * This interface extends BaseRepository which provides with the methods for
 * several CRUD operations.
 * 
 * @author Dharmesh Khandelwal
 * @since 1.0.0
 *
 */
@Repository
public interface KeyAliasRepository extends JpaRepository<KeyAlias, String> {

	/**
	 * Function to find keyalias by applicationId and referenceId
	 * 
	 * @param applicationId applicationId
	 * @param referenceId   referenceId
	 * @return list of keyalias
	 */
	List<KeyAlias> findByApplicationIdAndReferenceId(String applicationId, String referenceId);

	/**
	 * Function to find keyalias by applicationId
	 * 
	 * @param applicationId applicationId
	 * @return list of keyalias
	 */
	List<KeyAlias> findByApplicationId(String applicationId);

	/**
	 * Function to find keyalias by certificate thumbprint
	 * 
	 * @param certThumbprint hex encoded certificate thumbprint
	 * @return list of keyalias
	 */
	List<KeyAlias> findByCertThumbprint(String certThumbprint);

	/**
	 * Function to find keyalias by certificate thumbprint is null
	 * 
	 * @param 
	 * @return list of keyalias
	 */
	List<KeyAlias> findByCertThumbprintIsNull();

	/**
	 * Function to find keyalias by key unique identifieris null
	 * 
	 * @param 
	 * @return list of keyalias
	 */
	List<KeyAlias> findByUniqueIdentifierIsNull();

	/**
	 * Function to find keyalias by applicationId, referenceId and certThumbprint
	 * 
	 * @param applicationId applicationId
	 * @param referenceId   referenceId
	 * @param certThumbprint certThumbprint
	 * @return list of keyalias
	 */
	List<KeyAlias> findByApplicationIdAndReferenceIdAndCertThumbprint(String applicationId, String referenceId, String certThumbprint);

	/**
	 * Function to find keyalias by referenceId
	 * @param referenceId
	 * @return
	 */
	List<KeyAlias> findByReferenceId(String referenceId);

}
