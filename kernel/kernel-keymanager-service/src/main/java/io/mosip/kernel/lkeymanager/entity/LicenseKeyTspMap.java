package io.mosip.kernel.lkeymanager.entity;

import java.time.LocalDateTime;

import jakarta.persistence.AttributeOverride;
import jakarta.persistence.AttributeOverrides;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.IdClass;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinColumns;
import jakarta.persistence.OneToOne;
import jakarta.persistence.Table;

import io.mosip.kernel.lkeymanager.entity.id.LicenseKeyTspMapID;
import lombok.Data;

/**
 * Entity class for License key and TSP ID mapping.
 * 
 * @author Sagar Mahapatra
 * @since 1.0.0
 *
 */
@Data
@Entity
@IdClass(LicenseKeyTspMapID.class)
@Table(name = "tsp_licensekey_map")
public class LicenseKeyTspMap {
	/**
	 * Attributes of the primary key : TSP ID, License Key.
	 */
	@Id
	@AttributeOverrides({
			@AttributeOverride(name = "tsp_id", column = @Column(name = "tsp_id", nullable = false, length = 36)),
			@AttributeOverride(name = "license_key", column = @Column(name = "license_key", nullable = false, length = 255)) })
	private String tspId;
	
	private String licenseKey;
	/**
	 * The active state of licensekey-tsp mapping.
	 */
	@Column(name = "is_active", nullable = false)
	private boolean isActive;
	/**
	 * The map created by.
	 */
	@Column(name = "cr_by", nullable = false, length = 256)
	private String createdBy;
	/**
	 * The map created at.
	 */
	@Column(name = "cr_dtimes", nullable = false)
	private LocalDateTime createdDateTimes;
	/**
	 * The map updated by.
	 */
	@Column(name = "upd_by", length = 256)
	private String updatedBy;
	/**
	 * The map updated at.
	 */
	@Column(name = "upd_dtimes")
	private LocalDateTime updatedDTimes;
	/**
	 * The deletion state of map.
	 */
	@Column(name = "is_deleted")
	private boolean isDeleted;
	/**
	 * The deletion time of map.
	 */
	@Column(name = "del_dtimes")
	private LocalDateTime deletedDateTimes;
	/**
	 * One To One mapping.
	 */
	@OneToOne(fetch = FetchType.LAZY)
	@JoinColumns({ @JoinColumn(name = "license_key", insertable = false, updatable = false) })
	private LicenseKeyList licenseKeyList;
}
